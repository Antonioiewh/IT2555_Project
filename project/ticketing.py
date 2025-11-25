from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from models import (
    db, User, Ticket, TicketMessage, SupportAgent, TicketAssignment, 
    TicketEscalation, TicketCategory, KnowledgeBaseArticle
)
from forms import TicketForm, TicketReplyForm, TicketAssignForm, KnowledgeBaseForm
from decorators import role_required, admin_required
from sqlalchemy import and_, or_, func
import logging

# Create Blueprint
ticketing_bp = Blueprint('ticketing', __name__, url_prefix='/tickets')

# Clearance Level Constants
CLEARANCE_LEVELS = {
    'L1': 1,  # Basic support
    'L2': 2,  # Intermediate support
    'L3': 3,  # Advanced support
    'L4': 4,  # Critical/Security issues
    'L5': 5   # Admin-only escalations
}

PRIORITY_CLEARANCE_MAP = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'security': 5
}

def check_ticket_access(ticket, user, action='view'):
    """
    Check if user has access to ticket based on clearance level and ownership
    """
    # Users can always access their own tickets
    if ticket.user_id == user.user_id:
        return True
    
    # Check if user is a support agent
    agent = SupportAgent.query.filter_by(user_id=user.user_id, is_active=True).first()
    if not agent:
        return False
    
    # Get required clearance for ticket
    required_clearance = PRIORITY_CLEARANCE_MAP.get(ticket.priority, 1)
    
    # Check agent clearance level
    if agent.clearance_level < required_clearance:
        return False
    
    # For modify actions, check additional permissions
    if action in ['modify', 'assign', 'escalate']:
        if ticket.priority == 'security' and agent.clearance_level < 5:
            return False
        if ticket.priority == 'critical' and agent.clearance_level < 4:
            return False
    
    return True

# --- User Routes ---

@ticketing_bp.route('/')
@login_required
def index():
    """Main ticketing dashboard"""
    try:
        # Check if user is support agent
        agent = SupportAgent.query.filter_by(user_id=current_user.user_id, is_active=True).first()
        
        if agent:
            # Support agent view - show assigned tickets
            assigned_tickets = db.session.query(Ticket).join(
                TicketAssignment, Ticket.ticket_id == TicketAssignment.ticket_id
            ).filter(
                TicketAssignment.agent_id == agent.agent_id,
                TicketAssignment.is_active == True,
                Ticket.status.in_(['open', 'in_progress', 'pending'])
            ).order_by(Ticket.updated_at.desc()).all()
            
            # Get tickets user can access based on clearance - SIMPLIFIED VERSION
            if agent.clearance_level >= 5:
                # Level 5 agents can see all tickets
                accessible_tickets = Ticket.query.order_by(Ticket.updated_at.desc()).limit(20).all()
            elif agent.clearance_level >= 4:
                # Level 4+ can see critical and below
                accessible_tickets = Ticket.query.filter(
                    Ticket.priority.in_(['low', 'medium', 'high', 'critical'])
                ).order_by(Ticket.updated_at.desc()).limit(20).all()
            elif agent.clearance_level >= 3:
                # Level 3+ can see high and below
                accessible_tickets = Ticket.query.filter(
                    Ticket.priority.in_(['low', 'medium', 'high'])
                ).order_by(Ticket.updated_at.desc()).limit(20).all()
            elif agent.clearance_level >= 2:
                # Level 2+ can see medium and below
                accessible_tickets = Ticket.query.filter(
                    Ticket.priority.in_(['low', 'medium'])
                ).order_by(Ticket.updated_at.desc()).limit(20).all()
            else:
                # Level 1 can only see low priority
                accessible_tickets = Ticket.query.filter(
                    Ticket.priority == 'low'
                ).order_by(Ticket.updated_at.desc()).limit(20).all()
            
            return render_template('ticketing/agent_dashboard.html', 
                                 assigned_tickets=assigned_tickets,
                                 accessible_tickets=accessible_tickets,
                                 agent=agent)
        else:
            # Regular user view - show their tickets
            user_tickets = Ticket.query.filter_by(user_id=current_user.user_id)\
                .order_by(Ticket.updated_at.desc()).all()
            
            return render_template('ticketing/user_dashboard.html', tickets=user_tickets)
            
    except Exception as e:
        current_app.logger.error(f"Error in ticketing index: {str(e)}")
        flash('An error occurred while loading tickets.', 'error')
        return render_template('ticketing/user_dashboard.html', tickets=[])
        
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
        
        return render_template('ticketing/view_ticket.html', 
                             ticket=ticket, 
                             messages=messages,
                             assignment=assignment,
                             agent=agent,
                             form=form)
        
    except Exception as e:
        current_app.logger.error(f"Error viewing ticket: {str(e)}")
        flash('An error occurred while loading the ticket.', 'error')
        return redirect(url_for('ticketing.index'))

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

# --- Support Agent Routes ---

@ticketing_bp.route('/assign/<int:ticket_id>', methods=['POST'])
@role_required(['admin', 'support_agent'])
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
        
        required_clearance = PRIORITY_CLEARANCE_MAP.get(ticket.priority, 1)
        if agent.clearance_level < required_clearance:
            flash(f'Agent does not have sufficient clearance for {ticket.priority} priority tickets.', 'error')
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
@role_required(['admin', 'support_agent'])
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
        
        # Determine new priority level
        current_priority_level = PRIORITY_CLEARANCE_MAP.get(ticket.priority, 1)
        new_priority_level = min(current_priority_level + 1, 5)
        
        # Map back to priority name
        priority_map_reverse = {v: k for k, v in PRIORITY_CLEARANCE_MAP.items()}
        new_priority = priority_map_reverse.get(new_priority_level, 'high')
        
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
        
        # Update ticket priority
        ticket.priority = new_priority
        ticket.updated_at = datetime.utcnow()
        
        # Auto-reassign to agent with higher clearance if current agent can't handle new priority
        if current_agent.clearance_level < new_priority_level:
            # Deactivate current assignment
            TicketAssignment.query.filter_by(ticket_id=ticket_id, is_active=True).update({'is_active': False})
            
            # Find agent with required clearance
            suitable_agent = SupportAgent.query.filter(
                SupportAgent.clearance_level >= new_priority_level,
                SupportAgent.is_active == True,
                SupportAgent.agent_id != current_agent.agent_id
            ).first()
            
            if suitable_agent:
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
        
        return render_template('ticketing/manage_agents.html', 
                             agents=agents, 
                             available_users=users_without_agent)
        
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
        
        if not all([user_id, clearance_level, department]):
            flash('All fields are required.', 'error')
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
            created_by=current_user.user_id,
            created_at=datetime.utcnow(),
            is_active=True
        )
        
        db.session.add(agent)
        db.session.commit()
        
        user = User.query.get(user_id)
        flash(f'Support agent created for {user.username} with L{clearance_level} clearance.', 'success')
        
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
    """Auto-assign ticket to available agent based on priority and workload"""
    try:
        required_clearance = PRIORITY_CLEARANCE_MAP.get(ticket.priority, 1)
        
        # Find agents with required clearance level
        suitable_agents = SupportAgent.query.filter(
            SupportAgent.clearance_level >= required_clearance,
            SupportAgent.is_active == True
        ).all()
        
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