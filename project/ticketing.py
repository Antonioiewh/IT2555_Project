from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from models import (
    db, User, Ticket, TicketMessage, SupportAgent, TicketAssignment, 
    TicketEscalation, TicketCategory, KnowledgeBaseArticle, ClearanceLevel
)
from forms import TicketForm, TicketReplyForm, TicketAssignForm, KnowledgeBaseForm
from decorators import role_required, admin_required, agent_required
from sqlalchemy import and_, or_, func
import logging

# Create Blueprint
ticketing_bp = Blueprint('ticketing', __name__, url_prefix='/tickets')

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
# --- User Routes ---

@ticketing_bp.route('/')
@login_required
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
        
    except Exception as e:  # Fixed: changed 'in' to 'as'
        current_app.logger.error(f"Error loading assigned tickets: {str(e)}")
        flash('An error occurred while loading your tickets.', 'error')
        return redirect(url_for('ticketing.agent_dashboard'))


# unused   
@ticketing_bp.route('/create', methods=['GET', 'POST'])
@login_required
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
            try:
                from splunk_logger import splunk_logger
                splunk_logger.log_security_event('ticket_created', {
                    'ticket_id': ticket.ticket_id,
                    'priority': priority,
                    'classification': ticket.classification,
                    'category': category.name if category else 'Unknown'
                })
            except ImportError:
                pass
            
            flash(f'Ticket #{ticket.ticket_id} created successfully!', 'success')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket.ticket_id))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating ticket: {str(e)}")
            flash('An error occurred while creating the ticket.', 'error')
    
    return render_template('ticketing/create_ticket.html', form=form)

@ticketing_bp.route('/view/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    """View ticket details"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access permissions
        if not check_ticket_access(ticket, current_user):
            abort(403)
        
        # Get ticket messages
        messages = TicketMessage.query.filter_by(ticket_id=ticket_id)\
            .order_by(TicketMessage.created_at.asc()).all()
        
        # Get assignment info
        assignment = TicketAssignment.query.filter_by(
            ticket_id=ticket_id, is_active=True
        ).first()
        
        # Check if current user is support agent
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        
        form = TicketReplyForm()
        
        return render_template('ticketing/agent_view_ticket.html', 
                             ticket=ticket, 
                             messages=messages,
                             assignment=assignment,
                             agent=agent,
                             form=form)
        
    except Exception as e:
        current_app.logger.error(f"Error viewing ticket: {str(e)}")
        flash('An error occurred while loading the ticket.', 'error')
        return redirect(url_for('ticketing.index'))

# unused
@ticketing_bp.route('/reply/<int:ticket_id>', methods=['POST'])
@login_required
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

# Add this right after the take_ticket function (around line 402):

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

# unused
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
    """Escalate ticket to higher clearance level"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access permissions
        if not check_ticket_access(ticket, current_user, 'escalate'):
            abort(403)
        
        reason = request.form.get('reason', '').strip()
        if not reason:
            flash('Escalation reason is required.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Get current agent
        current_agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        if not current_agent:
            flash('Only support agents can escalate tickets.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Determine new priority level based on current priority
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
        
        db.session.commit()
        
        # Log escalation
        try:
            from splunk_logger import splunk_logger
            splunk_logger.log_security_event('ticket_escalated', {
                'ticket_id': ticket_id,
                'from_priority': escalation.previous_priority,
                'to_priority': new_priority,
                'escalated_by': current_user.username
            }, 'HIGH')
        except ImportError:
            pass
        
        flash(f'Ticket escalated from {escalation.previous_priority} to {new_priority} priority.', 'success')
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error escalating ticket: {str(e)}")
        flash('An error occurred while escalating the ticket.', 'error')
    
    return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))

@ticketing_bp.route('/close/<int:ticket_id>', methods=['POST'])
@login_required
def close_ticket(ticket_id):
    """Close ticket"""
    try:
        ticket = Ticket.query.get_or_404(ticket_id)
        
        # Check access permissions
        if not check_ticket_access(ticket, current_user, 'modify'):
            abort(403)
        
        resolution = request.form.get('resolution', '').strip()
        if not resolution:
            flash('Resolution description is required.', 'error')
            return redirect(url_for('ticketing.view_ticket', ticket_id=ticket_id))
        
        # Update ticket
        ticket.status = 'closed'
        ticket.resolution = resolution
        ticket.resolved_at = datetime.utcnow()
        ticket.updated_at = datetime.utcnow()
        
        # Add resolution message
        resolution_message = TicketMessage(
            ticket_id=ticket_id,
            user_id=current_user.user_id,
            message=f"**Ticket Closed**\n\nResolution: {resolution}",
            is_internal=False,
            created_at=datetime.utcnow()
        )
        
        db.session.add(resolution_message)
        db.session.commit()
        
        flash('Ticket closed successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error closing ticket: {str(e)}")
        flash('An error occurred while closing the ticket.', 'error')
    
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

# Move the get_classifications_at_or_below_level function to the top, right after check_ticket_access


