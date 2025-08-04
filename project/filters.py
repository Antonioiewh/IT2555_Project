# -- query filters for admin dashboard
import re
from flask import flash
from models import User, UserLog, Report, ModSecLog, ErrorLog

def apply_user_filters(query, search_query):
    """
    Apply search filters to User query based on search string.
    
    Args:
        query: SQLAlchemy query object for User model
        search_query: Search string with comma-separated filters
        
    Returns:
        Modified query object with filters applied
    """
    if not search_query:
        return query
        
    filters = search_query.split(',')
    for filter_item in filters:
        filter_item = filter_item.strip()  # Remove extra spaces
        filter_item = re.sub(r'[^\w=]', '', filter_item)  # Remove special characters except '='

        if 'id=' in filter_item:
            try:
                user_id = int(filter_item.split('id=')[1])
                query = query.filter(User.user_id == user_id)
            except ValueError:
                flash("Invalid ID format. ID must be a number.", "danger")
                
        elif 'username=' in filter_item:
            username = filter_item.split('username=')[1].strip()
            if re.match(r'^[a-zA-Z0-9_]+$', username):  # Allow alphanumeric and underscores
                query = query.filter(User.username.ilike(f"%{username}%"))
            else:
                flash("Invalid username format. Username must be alphanumeric.", "danger")
                
        elif 'phone=' in filter_item:
            phone = filter_item.split('phone=')[1].strip()
            if re.match(r'^\d+$', phone):  # Ensure phone contains only digits
                query = query.filter(User.phone_number.ilike(f"%{phone}%"))
            else:
                flash("Invalid phone format. Phone must contain only digits.", "danger")
                
        elif 'status=' in filter_item:
            status = filter_item.split('status=')[1].strip().lower()
            if status in ['online', 'offline', 'suspended', 'terminated']:  # Ensure status is valid
                query = query.filter(User.current_status.ilike(f"%{status}%"))
            else:
                flash("Invalid status format. Status must be 'online', 'offline', 'suspended', or 'terminated'.", "danger")
        else:
            flash("Invalid query format. Please use id=, username=, phone=, or status=.", "danger")
    
    return query

def apply_user_sorting(query, sort_by, order):
    """
    Apply sorting to User query.
    
    Args:
        query: SQLAlchemy query object for User model
        sort_by: Field to sort by ('id', 'username', 'registration_date')
        order: Sort order ('asc' or 'desc')
        
    Returns:
        Modified query object with sorting applied
    """
    if sort_by == 'username':
        query = query.order_by(User.username.asc() if order == 'asc' else User.username.desc())
    elif sort_by == 'registration_date':
        query = query.order_by(User.created_at.asc() if order == 'asc' else User.created_at.desc())
    else:  # Default sort by ID
        query = query.order_by(User.user_id.asc() if order == 'asc' else User.user_id.desc())
    
    return query

def apply_report_filters(query, search_query):
    """
    Apply search filters to Report query based on search string.
    """
    if not search_query:
        return query
        
    filters = search_query.split(',')
    for filter_item in filters:
        filter_item = filter_item.strip()
        if 'report_id=' in filter_item:
            try:
                report_id = int(filter_item.split('report_id=')[1])
                query = query.filter(Report.report_id == report_id)
            except ValueError:
                flash("Invalid report ID format. ID must be a number.", "danger")
        elif 'status=' in filter_item:
            status = filter_item.split('status=')[1].strip().lower()
            if status in ['open', 'in_review', 'action_taken', 'rejected']:
                query = query.filter(Report.status.ilike(f"%{status}%"))
            else:
                flash("Invalid status format. Status must be 'open', 'in_review', 'action_taken', or 'rejected'.", "danger")
        elif 'report_type=' in filter_item:
            report_type = filter_item.split('report_type=')[1].strip().lower()
            if report_type in ['spam', 'harassment', 'impersonation', 'inappropriate_content', 'fraud', 'other']:
                query = query.filter(Report.report_type.ilike(f"%{report_type}%"))
            else:
                flash("Invalid report type format.", "danger")
        else:
            flash("Invalid query format. Please use report_id=, status=, or report_type=.", "danger")
    
    return query

def apply_user_log_filters(query, search_query):
    """
    Apply search filters to UserLog query based on search string.
    """
    if not search_query:
        return query
        
    filters = search_query.split(',')
    for filter_item in filters:
        filter_item = filter_item.strip()
        if 'id=' in filter_item:
            try:
                log_id = int(filter_item.split('id=')[1])
                query = query.filter(UserLog.log_id == log_id)
            except ValueError:
                flash("Invalid ID format. ID must be a number.", "danger")
        elif 'user_id=' in filter_item:
            try:
                user_id = int(filter_item.split('user_id=')[1])
                query = query.filter(UserLog.user_id == user_id)
            except ValueError:
                flash("Invalid user ID format.", "danger")
        elif 'log_type=' in filter_item:
            log_type = filter_item.split('log_type=')[1].strip()
            query = query.filter(UserLog.log_type.ilike(f"%{log_type}%"))
        elif 'date=' in filter_item:
            date = filter_item.split('date=')[1].strip()
            query = query.filter(UserLog.log_timestamp.ilike(f"%{date}%"))
        else:
            flash("Invalid query format. Please use id=, user_id=, log_type=, or date=.", "danger")
    
    return query