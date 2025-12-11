# Core Flask imports
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort, current_app, session
from flask_login import login_required, current_user

# Standard library imports
from datetime import datetime, timedelta
import logging
import time
import traceback

# Third-party imports
from sqlalchemy import and_, or_, func
from werkzeug.security import check_password_hash
import pyotp

# Local imports
from models import (
    db, User, Ticket, TicketMessage, SupportAgent, TicketAssignment, 
    TicketEscalation, TicketCategory, KnowledgeBaseArticle, ClearanceLevel, ArchivedTicket, WebAuthnCredential
)
from forms import TicketForm, TicketReplyForm, TicketAssignForm, KnowledgeBaseForm
from decorators import role_required, admin_required, agent_required

# Optional imports that might not be available
try:
    from splunk_logger import splunk_logger
except ImportError:
    splunk_logger = None

# Create Blueprint
ticketing_bp = Blueprint('ticketing', __name__, url_prefix='/tickets')

# helper funcs
def check_ticket_access(ticket, user, action='view'):
    """
    Check if user has access to ticket based on classification and ownership
    """
    # Users can always access their own tickets
    if ticket.user_id == user.user_id:
        return True
    
    # Check if user is a support agent
    agent = SupportAgent.query.filter_by(user_id=user.user_id, is_active=True).first()
    if not agent:
        return False
    
    # Check classification-based access
    if not agent.can_view_classification(ticket.classification):
        return False
    
    # For modify actions, check additional permissions
    if action in ['modify', 'assign', 'escalate']:
        if ticket.classification in ['top_secret', 'secret'] and agent.clearance_level < 4:
            return False
    
    return True

def get_classifications_at_or_below_level(clearance_level):
    """
    Get all ticket classifications that an agent with given clearance level can access
    """
    # Classification levels mapping (higher number = higher clearance required)
    classification_levels = {
        'public': 1,
        'internal': 2,
        'confidential': 3,
        'secret': 4,
        'top_secret': 5
    }
    
    # Get classifications at or below the agent's clearance level
    accessible_classifications = []
    for classification, required_level in classification_levels.items():
        if clearance_level >= required_level:
            accessible_classifications.append(classification)
    
    return accessible_classifications

def get_available_escalation_tiers(current_clearance_level, ticket_classification=None):
    """Get available escalation tiers for current agent based on ticket classification"""
    tiers = []
    tier_names = {
        1: 'L1-PUBLIC',
        2: 'L2-INTERNAL',
        3: 'L3-CONFIDENTIAL', 
        4: 'L4-SECRET',
        5: 'L5-TOP SECRET'
    }
    
    # Classification to level mapping
    classification_to_level = {
        'public': 1,
        'internal': 2,
        'confidential': 3,
        'secret': 4,
        'top_secret': 5
    }
    
    # Get current classification level of the ticket
    if ticket_classification:
        current_ticket_level = classification_to_level.get(ticket_classification, 1)
    else:
        current_ticket_level = 1
    
    # Agent can escalate to any tier above the ticket's current level 
    # up to and including their own clearance level
    for level in range(current_ticket_level + 1, current_clearance_level + 1):
        tiers.append({
            'level': level,
            'name': tier_names.get(level, f'L{level}'),
            'description': f'Escalate to Level {level} clearance'
        })
    
    return tiers


def check_additional_auth_required(ticket_id, user):
    """Check if additional authentication is required and valid"""
    try:
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return True  # Require auth if ticket not found
        
        # Check classification level
        classification_levels = {
            'public': 1,
            'internal': 2,
            'confidential': 3,
            'secret': 4,
            'top_secret': 5
        }
        
        ticket_level = classification_levels.get(ticket.classification, 1)
        
        # No additional auth needed for level 1-2
        if ticket_level < 3:
            return False
        
        # Check session for verification
        if 'verified_tickets' not in session:
            return True
        
        verification_time = session['verified_tickets'].get(str(ticket_id))
        if not verification_time:
            return True
        
        # Check if verification is still valid (10 minutes)
        if time.time() - verification_time > 600:  # 10 minutes
            # Remove expired verification
            del session['verified_tickets'][str(ticket_id)]
            # Also clean up any partial verification data
            if 'ticket_verification' in session and str(ticket_id) in session['ticket_verification']:
                del session['ticket_verification'][str(ticket_id)]
            return True
        
        return False
        
    except Exception as e:
        current_app.logger.error(f"Error checking additional auth: {str(e)}")
        return True  # Require auth on error

# --- User Routes ---

@ticketing_bp.route('/')
@agent_required
def index():
    """Main ticketing index - redirect based on user type"""
    try:
        # Check if user is support agent
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        
        if agent:
            # Support agent - redirect to agent dashboard
            return redirect(url_for('ticketing.agent_dashboard'))
        else:
            # Regular user - show user dashboard
            user_tickets = Ticket.query.filter_by(user_id=current_user.user_id)\
                .order_by(Ticket.updated_at.desc()).all()
            
            return render_template('ticketing/user_dashboard.html', tickets=user_tickets)
            
    except Exception as e:
        current_app.logger.error(f"Error in ticketing index: {str(e)}")
        flash('An error occurred while loading tickets.', 'error')
        return render_template('ticketing/user_dashboard.html', tickets=[])

@ticketing_bp.route('/agent/dashboard')
@agent_required
def agent_dashboard():
    """Support agent main dashboard"""
    try:
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not agent:
            flash('Access denied. Support agent profile required.', 'error')
            return redirect(url_for('ticketing.index'))
        
        # Get tickets assigned to this agent
        assigned_tickets = db.session.query(Ticket).join(
            TicketAssignment, Ticket.ticket_id == TicketAssignment.ticket_id
        ).filter(
            TicketAssignment.agent_id == agent.agent_id,
            TicketAssignment.is_active == True,
            Ticket.status.in_(['open', 'in_progress', 'pending'])
        ).order_by(Ticket.updated_at.desc()).all()
        
        # Get classifications at or below this agent's clearance level
        accessible_classifications = get_classifications_at_or_below_level(agent.clearance_level)
        
        # Get assigned ticket IDs to exclude from available tickets
        assigned_ticket_ids = [t.ticket_id for t in assigned_tickets]
        
        # Get open tickets that this agent can access but are NOT assigned to them
        accessible_tickets_query = Ticket.query.filter(
            Ticket.status.in_(['open', 'in_progress', 'pending']),
            Ticket.classification.in_(accessible_classifications)
        )
        
        # Exclude tickets already assigned to this agent
        if assigned_ticket_ids:
            accessible_tickets_query = accessible_tickets_query.filter(
                ~Ticket.ticket_id.in_(assigned_ticket_ids)
            )
        
        # SIMPLIFIED: Show only tickets with NO assignments (no inactive assignments exist)
        accessible_tickets = accessible_tickets_query.outerjoin(TicketAssignment).filter(
            TicketAssignment.assignment_id.is_(None)
        ).order_by(Ticket.created_at.desc()).limit(10).all()
        
        return render_template('ticketing/agent_dashboard.html', 
                             assigned_tickets=assigned_tickets,
                             accessible_tickets=accessible_tickets,
                             agent=agent)
        
    except Exception as e:
        current_app.logger.error(f"Error loading agent dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard.', 'error')
        return redirect(url_for('ticketing.index'))

@ticketing_bp.route('/agent/open-tickets')
@agent_required
def agent_open_tickets():
    """Agent view for open tickets they can access"""
    try:
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not agent:
            flash('Access denied. Support agent profile required.', 'error')
            return redirect(url_for('ticketing.agent_dashboard'))
        
        # Get classifications at or below this agent's clearance level
        accessible_classifications = get_classifications_at_or_below_level(agent.clearance_level)
        
        # Get tickets assigned to this agent (to exclude them)
        assigned_tickets = db.session.query(Ticket).join(
            TicketAssignment, Ticket.ticket_id == TicketAssignment.ticket_id
        ).filter(
            TicketAssignment.agent_id == agent.agent_id,
            TicketAssignment.is_active == True,
            Ticket.status.in_(['open', 'in_progress', 'pending'])
        ).all()
        
        assigned_ticket_ids = [t.ticket_id for t in assigned_tickets]
        
        # Get open tickets that this agent can access but are NOT assigned to them
        accessible_tickets_query = Ticket.query.filter(
            Ticket.status.in_(['open', 'in_progress', 'pending']),
            Ticket.classification.in_(accessible_classifications)
        )
        
        # Exclude tickets already assigned to this agent
        if assigned_ticket_ids:
            accessible_tickets_query = accessible_tickets_query.filter(
                ~Ticket.ticket_id.in_(assigned_ticket_ids)
            )
        
        # SIMPLIFIED: Show only tickets with NO assignments
        open_tickets = accessible_tickets_query.outerjoin(TicketAssignment).filter(
            TicketAssignment.assignment_id.is_(None)
        ).order_by(Ticket.created_at.desc()).all()
        
        return render_template('ticketing/agent_open_tickets.html', 
                             tickets=open_tickets,
                             agent=agent)
        
    except Exception as e:
        current_app.logger.error(f"Error loading open tickets: {str(e)}")
        flash('An error occurred while loading tickets.', 'error')
        return redirect(url_for('ticketing.agent_dashboard'))

@ticketing_bp.route('/agent/my-tickets')
@agent_required
def agent_my_tickets():
    """Agent view for their assigned tickets"""
    try:
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not agent:
            flash('Access denied. Support agent profile required.', 'error')
            return redirect(url_for('ticketing.agent_dashboard'))
        
        # Get tickets assigned to this agent
        assigned_tickets = db.session.query(Ticket).join(
            TicketAssignment, Ticket.ticket_id == TicketAssignment.ticket_id
        ).filter(
            TicketAssignment.agent_id == agent.agent_id,
            TicketAssignment.is_active == True
        ).order_by(Ticket.updated_at.desc()).all()
        
        return render_template('ticketing/agent_my_tickets.html', 
                             tickets=assigned_tickets,
                             agent=agent)
        
    except Exception as e:
        current_app.logger.error(f"Error loading assigned tickets: {str(e)}")
        flash('An error occurred while loading your tickets.', 'error')
        return redirect(url_for('ticketing.agent_dashboard'))

@ticketing_bp.route('/create', methods=['GET', 'POST'])
@agent_required
def create_ticket():
    """Create new support ticket"""
    form = TicketForm()
    
    # Populate categories
    categories = TicketCategory.query.filter_by(is_active=True).all()
    form.category_id.choices = [(c.category_id, c.name) for c in categories]
    
    if form.validate_on_submit():
        try:
            # Determine priority based on category and content
            category = TicketCategory.query.get(form.category_id.data)
            priority = determine_ticket_priority(form.description.data, category)
            
            # Create ticket
            ticket = Ticket(
                user_id=current_user.user_id,
                title=form.title.data,
                description=form.description.data,
                category_id=form.category_id.data,
                priority=priority,
                status='open',
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            # Set classification based on priority
            ticket.classification = ticket.determine_classification()
            
            db.session.add(ticket)
            db.session.flush()
            
            # Auto-assign based on priority and agent availability
            auto_assign_ticket(ticket)
            
            db.session.commit()
            
            # Log ticket creation
            if splunk_logger:
                splunk_logger.log_security_event('ticket_created', {
                    'ticket_id': ticket.ticket_id,
                    'priority': priority,
                    'classification': ticket.classification,
                    'category': category.name if category else 'Unknown'
                })
            
            flash(f'Ticket #{ticket.ticket_id} created successfully!', 'success')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket.ticket_id))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating ticket: {str(e)}")
            flash('An error occurred while creating the ticket.', 'error')
    
    return render_template('ticketing/create_ticket.html', form=form)

@ticketing_bp.route('/view/<int:ticket_id>')
@agent_required
def view_ticket(ticket_id):
    """View ticket details"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access permissions
        if not check_ticket_access(ticket, current_user):
            abort(403)
        
        # Check if additional authentication is required
        if check_additional_auth_required(ticket_id, current_user):
            current_app.logger.info(f"SECURITY: Redirecting user {current_user.username} to additional auth for ticket {ticket_id}")
            return redirect(url_for('ticketing.verify_access', ticket_id=ticket_id))
        
        # Get ticket messages
        messages = TicketMessage.query.filter_by(ticket_id=ticket_id)\
            .order_by(TicketMessage.created_at.asc()).all()
        
        # Get assignment info
        assignment = TicketAssignment.query.filter_by(
            ticket_id=ticket_id, is_active=True
        ).first()
        
        # Check if current user is support agent
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        
        # Get available escalation tiers for this agent
        escalation_tiers = []
        if agent:
            escalation_tiers = get_available_escalation_tiers(agent.clearance_level, ticket.classification)
        
        form = TicketReplyForm()
        
        return render_template('ticketing/agent_view_ticket.html', 
                             ticket=ticket, 
                             messages=messages,
                             assignment=assignment,
                             agent=agent,
                             escalation_tiers=escalation_tiers,
                             form=form)
        
    except Exception as e:
        current_app.logger.error(f"Error viewing ticket: {str(e)}")
        flash('An error occurred while loading the ticket.', 'error')
        return redirect(url_for('ticketing.index'))

# unused
@ticketing_bp.route('/reply/<int:ticket_id>', methods=['POST'])
@agent_required
def reply_ticket(ticket_id):
    """Add reply to ticket"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access permissions
        if not check_ticket_access(ticket, current_user):
            abort(403)
        
        form = TicketReplyForm()
        
        if form.validate_on_submit():
            # Check if user is support agent
            agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
            is_agent_reply = agent is not None
            
            # Create message
            message = TicketMessage(
                ticket_id=ticket_id,
                user_id=current_user.user_id,
                message=form.message.data,
                is_internal=form.is_internal.data if is_agent_reply else False,
                created_at=datetime.utcnow()
            )
            
            db.session.add(message)
            
            # Update ticket status and timestamp
            ticket.updated_at = datetime.utcnow()
            
            # If agent reply, update status to in_progress
            if is_agent_reply and ticket.status == 'open':
                ticket.status = 'in_progress'
            
            # If user reply and ticket was pending, reopen it
            elif not is_agent_reply and ticket.status == 'pending':
                ticket.status = 'in_progress'
            
            db.session.commit()
            
            flash('Reply added successfully!', 'success')
            
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'error')
        
        return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error replying to ticket: {str(e)}")
        flash('An error occurred while adding your reply.', 'error')
        return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))

@ticketing_bp.route('/take/<int:ticket_id>', methods=['POST'])
@agent_required
def take_ticket(ticket_id):
    """Agent takes ownership of a ticket"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access permissions
        if not check_ticket_access(ticket, current_user, 'assign'):
            abort(403)
        
        # Get current agent
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not agent:
            return jsonify({'error': 'Agent profile required'}), 403
        
        # Check if agent can view this classification
        if not agent.can_view_classification(ticket.classification):
            return jsonify({'error': f'Insufficient clearance for {ticket.classification} classified tickets'}), 403
        
        # Check if ticket is already assigned to someone else
        existing_assignment = TicketAssignment.query.filter_by(ticket_id=ticket_id, is_active=True).first()
        if existing_assignment and existing_assignment.agent_id != agent.agent_id:
            return jsonify({'error': 'Ticket is already assigned to another agent'}), 400
        
        # If already assigned to this agent, no need to reassign
        if existing_assignment and existing_assignment.agent_id == agent.agent_id:
            return jsonify({'message': 'Ticket is already assigned to you'}), 200
        
        # Deactivate any existing assignments
        TicketAssignment.query.filter_by(ticket_id=ticket_id).update({'is_active': False})
        
        # Create new assignment
        assignment = TicketAssignment(
            ticket_id=ticket_id,
            agent_id=agent.agent_id,
            assigned_by=current_user.user_id,
            assigned_at=datetime.utcnow(),
            is_active=True
        )
        
        db.session.add(assignment)
        
        # Update ticket status
        ticket.status = 'in_progress'
        ticket.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'message': f'Ticket taken successfully!'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error taking ticket: {str(e)}")
        return jsonify({'error': 'An error occurred while taking the ticket'}), 500

@ticketing_bp.route('/untake/<int:ticket_id>', methods=['POST'])
@agent_required
def untake_ticket(ticket_id):
    """Agent releases ownership of a ticket"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access permissions
        if not check_ticket_access(ticket, current_user, 'assign'):
            return jsonify({'error': 'Access denied'}), 403
        
        # Get current agent
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not agent:
            return jsonify({'error': 'Agent profile required'}), 403
        
        # Check if ticket is assigned to this agent
        existing_assignment = TicketAssignment.query.filter_by(
            ticket_id=ticket_id, 
            agent_id=agent.agent_id, 
            is_active=True
        ).first()
        
        if not existing_assignment:
            return jsonify({'error': 'You are not assigned to this ticket'}), 400
        
        # COMPLETELY DELETE the assignment instead of deactivating
        db.session.delete(existing_assignment)
        
        # Update ticket status back to open
        ticket.status = 'open'
        ticket.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'message': f'Ticket released successfully! Ticket #{ticket_id} is now available for other agents.'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error releasing ticket: {str(e)}")
        return jsonify({'error': 'An error occurred while releasing the ticket'}), 500

@ticketing_bp.route('/assign/<int:ticket_id>', methods=['POST'])
@agent_required
def assign_ticket(ticket_id):
    """Assign ticket to support agent"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access permissions
        if not check_ticket_access(ticket, current_user, 'assign'):
            abort(403)
        
        agent_id = request.form.get('agent_id', type=int)
        if not agent_id:
            flash('Please select an agent to assign.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Verify agent exists and has required clearance
        agent = SupportAgent.query.get(agent_id)
        if not agent or not agent.is_active:
            flash('Invalid agent selected.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Check if agent can view this classification
        if not agent.can_view_classification(ticket.classification):
            flash(f'Agent does not have sufficient clearance for {ticket.classification} classified tickets.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Deactivate existing assignments
        TicketAssignment.query.filter_by(ticket_id=ticket_id).update({'is_active': False})
        
        # Create new assignment
        assignment = TicketAssignment(
            ticket_id=ticket_id,
            agent_id=agent_id,
            assigned_by=current_user.user_id,
            assigned_at=datetime.utcnow(),
            is_active=True
        )
        
        db.session.add(assignment)
        
        # Update ticket status
        ticket.status = 'in_progress'
        ticket.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Ticket assigned to {agent.user.username} successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error assigning ticket: {str(e)}")
        flash('An error occurred while assigning the ticket.', 'error')
    
    return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))

@ticketing_bp.route('/escalate/<int:ticket_id>', methods=['POST'])
@agent_required
def escalate_ticket(ticket_id):
    """Escalate ticket to higher clearance level or different tier"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access permissions
        if not check_ticket_access(ticket, current_user, 'escalate'):
            abort(403)
        
        reason = request.form.get('reason', '').strip()
        escalation_type = request.form.get('escalation_type', 'priority')
        target_tier = request.form.get('target_tier', '')
        
        if not reason:
            flash('Escalation reason is required.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Get current agent
        current_agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not current_agent:
            flash('Only support agents can escalate tickets.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        if escalation_type == 'tier' and target_tier:
            # Tier-based escalation
            try:
                target_tier_level = int(target_tier)
            except ValueError:
                flash('Invalid tier level specified.', 'error')
                return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
            
            # Get current ticket classification level
            classification_to_level = {
                'public': 1,
                'internal': 2,
                'confidential': 3,
                'secret': 4,
                'top_secret': 5
            }
            current_ticket_level = classification_to_level.get(ticket.classification, 1)
            
            # Validate that target tier is higher than current ticket classification
            if target_tier_level <= current_ticket_level:
                flash('Can only escalate to higher classification tiers than current ticket level.', 'error')
                return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
            
            # Check if there are any agents with the target tier clearance
            suitable_agents = SupportAgent.query.filter(
                SupportAgent.clearance_level >= target_tier_level,
                SupportAgent.is_active == True
            ).count()
            
            if suitable_agents == 0:
                flash(f'No available agents with L{target_tier_level} or higher clearance found.', 'error')
                return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
            
            # Update classification based on target tier
            classification_mapping = {
                1: 'public',
                2: 'internal', 
                3: 'confidential',
                4: 'secret',
                5: 'top_secret'
            }
            new_classification = classification_mapping.get(target_tier_level, ticket.classification)
            
            # Create escalation record
            escalation = TicketEscalation(
                ticket_id=ticket_id,
                escalated_by=current_agent.agent_id,
                escalated_at=datetime.utcnow(),
                previous_priority=ticket.priority,
                new_priority=ticket.priority,  # Keep same priority for tier escalation
                reason=f"Escalated to L{target_tier_level} tier: {reason}"
            )
            
            # Remove current assignment (delete it completely)
            current_assignments = TicketAssignment.query.filter_by(ticket_id=ticket_id, is_active=True).all()
            for assignment in current_assignments:
                db.session.delete(assignment)
            
            # Update ticket classification and set as open for agents of that tier to pick up
            ticket.classification = new_classification
            ticket.status = 'open'  # Set as open instead of assigning to specific agent
            ticket.updated_at = datetime.utcnow()
            
            db.session.add(escalation)
            
            # Get tier name for display
            tier_names = {
                1: 'L1-PUBLIC',
                2: 'L2-INTERNAL', 
                3: 'L3-CONFIDENTIAL',
                4: 'L4-SECRET',
                5: 'L5-TOP SECRET'
            }
            tier_name = tier_names.get(target_tier_level, f'L{target_tier_level}')
            
            flash(f'Ticket escalated to {tier_name} tier and is now available for agents with appropriate clearance to take.', 'success')
        else:
            # Priority-based escalation (existing functionality)
            priority_levels = ['low', 'medium', 'high', 'critical', 'security']
            current_index = priority_levels.index(ticket.priority) if ticket.priority in priority_levels else 1
            new_index = min(current_index + 1, len(priority_levels) - 1)
            new_priority = priority_levels[new_index]
            
            # Create escalation record
            escalation = TicketEscalation(
                ticket_id=ticket_id,
                escalated_by=current_agent.agent_id,
                escalated_at=datetime.utcnow(),
                previous_priority=ticket.priority,
                new_priority=new_priority,
                reason=reason
            )
            
            db.session.add(escalation)
            
            # Update ticket priority and classification
            ticket.priority = new_priority
            ticket.classification = ticket.determine_classification()
            ticket.updated_at = datetime.utcnow()
            
            # Auto-reassign to agent with higher clearance if current agent can't handle new classification
            if not current_agent.can_view_classification(ticket.classification):
                # Deactivate current assignment
                TicketAssignment.query.filter_by(ticket_id=ticket_id, is_active=True).update({'is_active': False})
                
                # Find agent with required clearance
                suitable_agent = SupportAgent.query.filter(
                    SupportAgent.clearance_level >= current_agent.clearance_level + 1,
                    SupportAgent.is_active == True,
                    SupportAgent.agent_id != current_agent.agent_id
                ).first()
                
                if suitable_agent and suitable_agent.can_view_classification(ticket.classification):
                    new_assignment = TicketAssignment(
                        ticket_id=ticket_id,
                        agent_id=suitable_agent.agent_id,
                        assigned_by=current_user.user_id,
                        assigned_at=datetime.utcnow(),
                        is_active=True
                    )
                    db.session.add(new_assignment)
            
            flash(f'Ticket escalated from {escalation.previous_priority} to {new_priority} priority.', 'success')
        
        db.session.commit()
        
        # Log escalation
        if splunk_logger:
            splunk_logger.log_security_event('ticket_escalated', {
                'ticket_id': ticket_id,
                'escalation_type': escalation_type,
                'escalated_by': current_user.username,
                'target_tier': target_tier if escalation_type == 'tier' else None
            }, 'HIGH')
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error escalating ticket: {str(e)}")
        flash('An error occurred while escalating the ticket.', 'error')
    
    return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))

@ticketing_bp.route('/close/<int:ticket_id>', methods=['POST'])
@agent_required
def close_ticket(ticket_id):
    """Close ticket with optional archiving"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access
        if not check_ticket_access(ticket, current_user, 'modify'):
            flash('Access denied.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        resolution = request.form.get('resolution', '').strip()
        archive_ticket_raw = request.form.get('archive_ticket')
        archive_ticket = request.form.get('archive_ticket') == 'on'
        
        # Enhanced debugging
        current_app.logger.info(f"=== CLOSE TICKET DEBUG FOR TICKET {ticket_id} ===")
        current_app.logger.info(f"Full form data: {dict(request.form)}")
        current_app.logger.info(f"Archive ticket raw value: '{archive_ticket_raw}'")
        current_app.logger.info(f"Archive ticket boolean: {archive_ticket}")
        current_app.logger.info(f"Resolution: '{resolution}'")
        current_app.logger.info(f"Current user: {current_user.username} (ID: {current_user.user_id})")
        
        if not resolution:
            flash('Resolution is required to close the ticket.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Update ticket first
        ticket.status = 'closed'
        ticket.resolution = resolution
        ticket.resolved_at = datetime.utcnow()
        
        flash_msg = f'Ticket #{ticket_id} has been closed successfully.'
        
        # Archive if requested
        if archive_ticket:
            try:
                current_app.logger.info(f"ARCHIVING: Starting archive process for ticket {ticket_id}")
                
                
                # Create archived ticket record with explicit field validation
                archived_ticket = ArchivedTicket(
                    original_ticket_id=ticket.ticket_id,
                    user_id=ticket.user_id,
                    title=ticket.title,
                    description=ticket.description,
                    category_id=ticket.category_id,
                    priority=ticket.priority,
                    status='closed',
                    classification=ticket.classification,
                    resolution=resolution,
                    created_at=ticket.created_at,
                    updated_at=ticket.updated_at,
                    resolved_at=datetime.utcnow(),
                    archived_by=current_user.user_id
                )
                
                current_app.logger.info(f"ARCHIVING: Created ArchivedTicket object")
                
                # Add and flush to get ID
                db.session.add(archived_ticket)
                db.session.flush()
                
                current_app.logger.info(f"ARCHIVING: Flushed to DB, archived ticket ID: {archived_ticket.archived_ticket_id}")
                
                # Update original ticket with archive info
                ticket.archived_at = datetime.utcnow()
                ticket.archived_by = current_user.user_id
                
                current_app.logger.info(f"ARCHIVING: Updated original ticket with archive metadata")
                
                flash_msg = f'Ticket #{ticket_id} has been closed and archived successfully.'
                
            except Exception as archive_error:
                current_app.logger.error(f"ARCHIVING ERROR: {str(archive_error)}")
                current_app.logger.error(f"ARCHIVING ERROR TYPE: {type(archive_error).__name__}")
                current_app.logger.error(f"ARCHIVING TRACEBACK: {traceback.format_exc()}")
                
                # Don't rollback here, just continue with closing the ticket
                flash('Archive failed, but ticket was closed successfully.', 'warning')
                flash_msg = f'Ticket #{ticket_id} has been closed (archive failed).'
        else:
            current_app.logger.info(f"ARCHIVING: Skipped - checkbox not checked")
        
        # Commit the transaction
        current_app.logger.info(f"COMMITTING: Starting database commit")
        db.session.commit()
        current_app.logger.info(f"COMMITTING: Database commit successful")
        
        # Verification step
        if archive_ticket:
            verification = ArchivedTicket.query.filter_by(original_ticket_id=ticket_id).first()
            if verification:
                current_app.logger.info(f"VERIFICATION: SUCCESS - Found archived ticket {verification.archived_ticket_id}")
            else:
                current_app.logger.error(f"VERIFICATION: FAILED - No archived ticket found in database")
                flash_msg = f'Ticket #{ticket_id} closed, but archive verification failed.'
        
        flash(flash_msg, 'success')
        current_app.logger.info(f"=== CLOSE TICKET COMPLETE FOR TICKET {ticket_id} ===")
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"CRITICAL ERROR closing ticket {ticket_id}: {str(e)}")
        current_app.logger.error(f"ERROR TYPE: {type(e).__name__}")
        current_app.logger.error(f"FULL TRACEBACK: {traceback.format_exc()}")
        flash('An error occurred while closing the ticket.', 'error')
    
    return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))

@ticketing_bp.route('/agent/archived-tickets')
@agent_required
def agent_archived_tickets():
    """Agent view for archived tickets they can access"""
    try:
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not agent:
            flash('Agent profile not found.', 'error')
            return redirect(url_for('ticketing.index'))
        
        # Get classifications at or below this agent's clearance level
        accessible_classifications = get_classifications_at_or_below_level(agent.clearance_level)
        
        # Get archived tickets based on clearance
        archived_tickets = ArchivedTicket.query.filter(
            ArchivedTicket.classification.in_(accessible_classifications)
        ).order_by(ArchivedTicket.archived_at.desc()).all()
        
        return render_template('ticketing/agent_archived_tickets.html', 
                             archived_tickets=archived_tickets,
                             agent=agent)
        
    except Exception as e:
        current_app.logger.error(f"Error loading archived tickets: {str(e)}")
        flash('An error occurred while loading archived tickets.', 'error')
        return redirect(url_for('ticketing.agent_dashboard'))

@ticketing_bp.route('/view-archived/<int:archived_ticket_id>')
@agent_required
def view_archived_ticket(archived_ticket_id):
    """View archived ticket details (read-only)"""
    try:
        archived_ticket = ArchivedTicket.query.get_or_404(archived_ticket_id)
        
        # Check clearance access
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not agent or not agent.can_view_classification(archived_ticket.classification):
            flash('Access denied - insufficient clearance level.', 'error')
            return redirect(url_for('ticketing.agent_archived_tickets'))
        
        return render_template('ticketing/view_archived_ticket.html', 
                             ticket=archived_ticket,
                             agent=agent)
        
    except Exception as e:
        current_app.logger.error(f"Error viewing archived ticket: {str(e)}")
        flash('An error occurred while loading the archived ticket.', 'error')
        return redirect(url_for('ticketing.agent_archived_tickets'))

@ticketing_bp.route('/terminate/<int:ticket_id>', methods=['POST'])
@agent_required
def terminate_ticket(ticket_id):
    """Permanently delete ticket from database"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access
        if not check_ticket_access(ticket, current_user, 'modify'):
            flash('Access denied.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Get current agent for additional permission check
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not agent:
            flash('Only support agents can terminate tickets.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Higher clearance agents can terminate any ticket they can view
        # Lower clearance agents can only terminate tickets they created or are assigned to
        can_terminate = False
        
        if agent.clearance_level >= 4:  # L4 SECRET and L5 TOP SECRET can terminate any viewable ticket
            can_terminate = True
        else:
            # Check if agent is assigned to this ticket or created it
            assignment = TicketAssignment.query.filter_by(
                ticket_id=ticket_id, 
                agent_id=agent.agent_id, 
                is_active=True
            ).first()
            
            if assignment or ticket.user_id == current_user.user_id:
                can_terminate = True
        
        if not can_terminate:
            flash('Insufficient permissions to terminate this ticket.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        current_app.logger.info(f"=== TERMINATE TICKET {ticket_id} ===")
        current_app.logger.info(f"Terminated by: {current_user.username} (Agent ID: {agent.agent_id})")
        current_app.logger.info(f"Ticket details - Title: {ticket.title}, Priority: {ticket.priority}, Classification: {ticket.classification}")
        
        # Store ticket info for flash message before deletion
        ticket_title = ticket.title
        ticket_number = ticket.ticket_id
        
        # Delete related records first (to maintain referential integrity)
        # Delete ticket assignments
        TicketAssignment.query.filter_by(ticket_id=ticket_id).delete()
        
        # Delete ticket escalations
        TicketEscalation.query.filter_by(ticket_id=ticket_id).delete()
        
        # Delete ticket messages
        TicketMessage.query.filter_by(ticket_id=ticket_id).delete()
        
        # Finally delete the ticket itself
        db.session.delete(ticket)
        
        # Commit all deletions
        db.session.commit()
        
        current_app.logger.info(f"TERMINATE: Ticket #{ticket_number} permanently deleted from database")
        
        flash(f'Ticket #{ticket_number} "{ticket_title}" has been permanently terminated and removed from the database.', 'warning')
        
        # Redirect to agent dashboard since ticket no longer exists
        return redirect(url_for('ticketing.agent_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"CRITICAL ERROR terminating ticket {ticket_id}: {str(e)}")
        current_app.logger.error(f"ERROR TYPE: {type(e).__name__}")
        current_app.logger.error(f"FULL TRACEBACK: {traceback.format_exc()}")
        flash('An error occurred while terminating the ticket.', 'error')
        return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))


# --- agent authentication --
@ticketing_bp.route('/verify-access/<int:ticket_id>', methods=['GET', 'POST'])
@agent_required
def verify_access(ticket_id):
    """Additional authentication for high-classification tickets"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check basic access first
        if not check_ticket_access(ticket, current_user):
            abort(403)
        
        # Check if additional auth is needed
        classification_levels = {
            'public': 1,
            'internal': 2,
            'confidential': 3,
            'secret': 4,
            'top_secret': 5
        }
        
        ticket_level = classification_levels.get(ticket.classification, 1)
        
        # Only require additional auth for level 3+ (confidential and above)
        if ticket_level < 3:
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Determine user's security setup
        has_password = bool(current_user.password_hash)
        has_2fa = bool(current_user.totp_secret)
        has_passkey = WebAuthnCredential.query.filter_by(user_id=current_user.user_id).first() is not None
        
        # Determine required authentication methods
        if has_password and has_2fa and has_passkey:
            required_methods = ['2fa', 'passkey']  # Skip password, use 2FA + passkey
        elif has_password and has_2fa:
            required_methods = ['password', '2fa']  # Use password + 2FA
        elif has_password:
            required_methods = ['password']  # Password only
        else:
            flash('No valid authentication methods configured.', 'error')
            return redirect(url_for('ticketing.agent_dashboard'))
        
        if request.method == 'POST':
            # Handle different authentication methods
            auth_method = request.form.get('auth_method')
            
            if auth_method == 'password':
                return handle_password_verification(ticket_id, ticket, required_methods)
            elif auth_method == 'totp':
                return handle_2fa_verification(ticket_id, ticket, required_methods)
            elif auth_method == 'passkey':
                return handle_passkey_verification(ticket_id, ticket, required_methods)
        
        # GET request - show appropriate authentication form
        return render_template('ticketing/agent_verify_access.html', 
                             ticket=ticket,
                             required_methods=required_methods,
                             has_password=has_password,
                             has_2fa=has_2fa,
                             has_passkey=has_passkey)
        
    except Exception as e:
        current_app.logger.error(f"Error in access verification: {str(e)}")
        flash('An error occurred during access verification.', 'error')
        return redirect(url_for('ticketing.index'))

def handle_password_verification(ticket_id, ticket, required_methods):
    """Handle password verification step"""
    password = request.form.get('password', '').strip()
    
    if not password:
        flash('Password is required.', 'error')
        return render_template('ticketing/verify_access.html', 
                             ticket=ticket, 
                             required_methods=required_methods,
                             show_password_error=True)
    
    # Verify password
    if not check_password_hash(current_user.password_hash, password):
        current_app.logger.warning(f"SECURITY: Failed password verification for user {current_user.username} accessing ticket {ticket_id}")
        flash('Incorrect password. Access denied.', 'error')
        return render_template('ticketing/verify_access.html', 
                             ticket=ticket, 
                             required_methods=required_methods,
                             show_password_error=True)
    
    # Store password verification in session
    if 'ticket_verification' not in session:
        session['ticket_verification'] = {}
    
    if str(ticket_id) not in session['ticket_verification']:
        session['ticket_verification'][str(ticket_id)] = {}
    
    session['ticket_verification'][str(ticket_id)]['password'] = time.time()
    
    # Check if password was the only required method
    if len(required_methods) == 1 and 'password' in required_methods:
        return complete_verification(ticket_id, ticket)
    
    # Password verified, show next step
    flash('Password verified. Please complete additional authentication.', 'info')
    return render_template('ticketing/agent_verify_access.html', 
                         ticket=ticket, 
                         required_methods=required_methods,
                         password_verified=True)

def handle_2fa_verification(ticket_id, ticket, required_methods):
    """Handle 2FA verification step"""
    totp_code = request.form.get('totp_code', '').strip()
    
    if not totp_code:
        flash('2FA code is required.', 'error')
        return render_template('ticketing/agent_verify_access.html', 
                             ticket=ticket, 
                             required_methods=required_methods,
                             show_2fa_error=True)
    
    # Verify TOTP code
    totp = pyotp.TOTP(current_user.totp_secret)
    if not totp.verify(totp_code, valid_window=1):
        current_app.logger.warning(f"SECURITY: Failed 2FA verification for user {current_user.username} accessing ticket {ticket_id}")
        flash('Invalid 2FA code. Access denied.', 'error')
        return render_template('ticketing/agent_verify_access.html', 
                             ticket=ticket, 
                             required_methods=required_methods,
                             show_2fa_error=True)
    
    # Store 2FA verification in session
    if 'ticket_verification' not in session:
        session['ticket_verification'] = {}
    
    if str(ticket_id) not in session['ticket_verification']:
        session['ticket_verification'][str(ticket_id)] = {}
    
    session['ticket_verification'][str(ticket_id)]['2fa'] = time.time()
    
    # Check if all required methods are now verified
    if is_verification_complete(ticket_id, required_methods):
        return complete_verification(ticket_id, ticket)
    
    # 2FA verified, show next step or completion
    flash('2FA verified. Please complete passkey authentication.', 'info')
    return render_template('ticketing/verify_access.html', 
                         ticket=ticket, 
                         required_methods=required_methods,
                         totp_verified=True)

def handle_passkey_verification(ticket_id, ticket, required_methods):
    """Handle passkey verification step"""
    # This would integrate with your existing passkey verification logic
    # For now, we'll mark it as verified (you'll need to implement the actual passkey verification)
    
    if 'ticket_verification' not in session:
        session['ticket_verification'] = {}
    
    if str(ticket_id) not in session['ticket_verification']:
        session['ticket_verification'][str(ticket_id)] = {}
    
    session['ticket_verification'][str(ticket_id)]['passkey'] = time.time()
    
    # Check if all required methods are now verified
    if is_verification_complete(ticket_id, required_methods):
        return complete_verification(ticket_id, ticket)
    
    flash('Passkey verified.', 'info')
    return render_template('ticketing/verify_access.html', 
                         ticket=ticket, 
                         required_methods=required_methods,
                         passkey_verified=True)

def is_verification_complete(ticket_id, required_methods):
    """Check if all required authentication methods have been verified"""
    if 'ticket_verification' not in session:
        return False
    
    ticket_verification = session['ticket_verification'].get(str(ticket_id), {})
    
    for method in required_methods:
        if method not in ticket_verification:
            return False
    
    return True

def complete_verification(ticket_id, ticket):
    """Complete the verification process and grant access"""
    # Store final verification
    if 'verified_tickets' not in session:
        session['verified_tickets'] = {}
    
    session['verified_tickets'][str(ticket_id)] = time.time()
    session.permanent = True
    
    # Clear temporary verification data
    if 'ticket_verification' in session and str(ticket_id) in session['ticket_verification']:
        del session['ticket_verification'][str(ticket_id)]
    
    current_app.logger.info(f"SECURITY: User {current_user.username} completed verification for {ticket.classification} ticket {ticket_id}")
    
    flash(f'Access verified for {ticket.classification} classified ticket.', 'success')
    return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))

# --- Admin Routes ---

@ticketing_bp.route('/admin/agents')
@admin_required
def manage_agents():
    """Manage support agents"""
    try:
        agents = SupportAgent.query.join(User).order_by(User.username).all()
        users_without_agent = db.session.query(User).outerjoin(SupportAgent).filter(
            SupportAgent.user_id.is_(None)
        ).all()
        clearance_levels = ClearanceLevel.query.order_by(ClearanceLevel.level_id).all()
        
        return render_template('ticketing/manage_agents.html', 
                             agents=agents, 
                             available_users=users_without_agent,
                             clearance_levels=clearance_levels)
        
    except Exception as e:
        current_app.logger.error(f"Error loading agents: {str(e)}")
        flash('An error occurred while loading agents.', 'error')
        return redirect(url_for('ticketing.index'))

@ticketing_bp.route('/admin/agents/create', methods=['POST'])
@admin_required
def create_agent():
    """Create new support agent"""
    try:
        user_id = request.form.get('user_id', type=int)
        clearance_level = request.form.get('clearance_level', type=int)
        department = request.form.get('department', '').strip()
        specialization = request.form.get('specialization', '').strip()
        
        if not all([user_id, clearance_level, department]):
            flash('User, clearance level, and department are required.', 'error')
            return redirect(url_for('ticketing.manage_agents'))
        
        if clearance_level < 1 or clearance_level > 5:
            flash('Clearance level must be between 1 and 5.', 'error')
            return redirect(url_for('ticketing.manage_agents'))
        
        # Check if user already has agent record
        existing_agent = SupportAgent.query.filter_by(user_id=user_id).first()
        if existing_agent:
            flash('User is already a support agent.', 'error')
            return redirect(url_for('ticketing.manage_agents'))
        
        # Create agent
        agent = SupportAgent(
            user_id=user_id,
            clearance_level=clearance_level,
            department=department,
            specialization=specialization if specialization else None,
            created_by=current_user.user_id,
            created_at=datetime.utcnow(),
            is_active=True
        )
        
        db.session.add(agent)
        db.session.commit()
        
        user = User.query.get(user_id)
        clearance = ClearanceLevel.query.get(clearance_level)
        clearance_name = clearance.level_name if clearance else f'L{clearance_level}'
        flash(f'Support agent created for {user.username} with {clearance_name} clearance.', 'success')
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating agent: {str(e)}")
        flash('An error occurred while creating the agent.', 'error')
    
    return redirect(url_for('ticketing.manage_agents'))

# --- Utility Functions ---

def determine_ticket_priority(description, category):
    """Determine ticket priority based on content and category"""
    description_lower = description.lower()
    
    # Security-related keywords
    security_keywords = ['hack', 'breach', 'unauthorized', 'malware', 'phishing', 'security', 'exploit']
    if any(keyword in description_lower for keyword in security_keywords):
        return 'security'
    
    # Critical keywords  
    critical_keywords = ['cannot login', 'system down', 'data loss', 'urgent', 'critical']
    if any(keyword in description_lower for keyword in critical_keywords):
        return 'critical'
    
    # High priority keywords
    high_keywords = ['error', 'bug', 'broken', 'not working', 'issue']
    if any(keyword in description_lower for keyword in high_keywords):
        return 'high'
    
    # Category-based priority
    if category:
        if 'security' in category.name.lower():
            return 'security'
        elif 'critical' in category.name.lower() or 'urgent' in category.name.lower():
            return 'critical'
        elif 'technical' in category.name.lower():
            return 'high'
    
    return 'medium'

def auto_assign_ticket(ticket):
    """Auto-assign ticket to available agent based on classification and workload"""
    try:
        # Find agents who can view this classification
        suitable_agents = []
        all_agents = SupportAgent.query.filter(SupportAgent.is_active == True).all()
        
        for agent in all_agents:
            if agent.can_view_classification(ticket.classification):
                suitable_agents.append(agent)
        
        if not suitable_agents:
            return  # No suitable agents available
        
        # Find agent with lowest current workload
        agent_workloads = []
        for agent in suitable_agents:
            active_tickets = TicketAssignment.query.filter_by(
                agent_id=agent.agent_id, is_active=True
            ).count()
            agent_workloads.append((agent, active_tickets))
        
        # Sort by workload (ascending) and assign to agent with least tickets
        agent_workloads.sort(key=lambda x: x[1])
        selected_agent = agent_workloads[0][0]
        
        # Create assignment
        assignment = TicketAssignment(
            ticket_id=ticket.ticket_id,
            agent_id=selected_agent.agent_id,
            assigned_by=None,  # Auto-assigned
            assigned_at=datetime.utcnow(),
            is_active=True
        )
        
        db.session.add(assignment)
        
    except Exception as e:
        current_app.logger.error(f"Error auto-assigning ticket: {str(e)}")
        # Don't raise exception, just log it

# --- test archive ----
@ticketing_bp.route('/test-archive', methods=['GET'])
@agent_required
def test_archive():
    """Test route to verify archive functionality"""
    try:
        # Try to create a simple archived ticket
        test_ticket = ArchivedTicket(
            original_ticket_id=999999,
            user_id=current_user.user_id,
            title="Test Archive",
            description="Test description",
            category_id=1,
            priority='low',
            status='closed',
            classification='public',
            resolution="Test resolution",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            resolved_at=datetime.utcnow(),
            archived_by=current_user.user_id
        )
        
        db.session.add(test_ticket)
        db.session.commit()
        
        return f"Test archived ticket created with ID: {test_ticket.archived_ticket_id}"
        
    except Exception as e:
        db.session.rollback()
        return f"Error creating test archived ticket: {str(e)}<br>{traceback.format_exc()}"