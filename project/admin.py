from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user
from datetime import datetime
import os

# Import your models and other dependencies
from models import db, User, Report, ModSecLog, ErrorLog, UserLog, Notification, Role, user_role_assignments
from decorators import admin_required
from forms import UpdateUserStatusForm, UpdateReportStatusForm
from filters import apply_user_filters, apply_user_sorting, apply_report_filters, apply_user_log_filters
from parse_test import parse_modsec_audit_log, parse_error_log
from file_validate import validate_file_security
from models import db, User, Report, ModSecLog, ErrorLog, UserLog, Notification, Role, user_role_assignments, AdminAction
from content_checker import SensitiveContentChecker, check_sensitive_content

# Create Blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Move all your admin routes here, removing the /admin prefix from route decorators

@admin_bp.route('/users_dashboard')
@admin_required
def manage_users():
    # Get query parameters
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id')  # Default sort by ID
    order = request.args.get('order', 'asc')  # Default order is ascending

    # Base query
    query = User.query

    # Apply filters using the separate function
    query = apply_user_filters(query, search_query)
    
    # Apply sorting using the separate function
    query = apply_user_sorting(query, sort_by, order)

    users = query.all()

    total_users = User.query.count()
    online_users = User.query.filter_by(current_status='online').count()
    offline_users = User.query.filter_by(current_status='offline').count()

    return render_template(
        'oldadmin/AdminManageUsers.html',
        total_users=total_users,
        online_users=online_users,
        offline_users=offline_users,
        users=users,
        sort_by=sort_by,
        order=order,
        search_query=search_query,
        form=UpdateUserStatusForm()
    )

@admin_bp.route('/manage_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def manage_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin.manage_users'))

    form = UpdateUserStatusForm()
    if form.validate_on_submit():
        new_status = form.status.data
        if new_status in ['offline', 'online', 'suspended', 'terminated']:
            user.current_status = new_status
            db.session.commit()
            flash(f"User {user.username}'s status updated to {new_status}.", "success")
        else:
            flash("Invalid status.", "danger")
        return redirect(url_for('admin.manage_users'))

    return render_template('oldadmin/AdminChangeUserStatus.html', user=user, form=form)

@admin_bp.route('/suspend_user/<int:user_id>', methods=['POST'])
@admin_required
def suspend_user(user_id):
    """Suspend a user account"""
    user = User.query.get_or_404(user_id)
    
    if user.has_role('admin'):
        flash('Cannot suspend an admin user.', 'error')
        return redirect(url_for('admin.manage_users'))
    
    user.current_status = 'suspended'
    db.session.commit()
    
    # Log the action
    from flask import current_app
    current_app.logger.info(f"User {user.username} suspended by {current_user.username}")
    
    flash(f'User {user.username} has been suspended.', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/terminate_user/<int:user_id>', methods=['POST'])
@admin_required
def terminate_user(user_id):
    """Terminate a user account permanently"""
    user = User.query.get_or_404(user_id)
    
    if user.has_role('admin'):
        flash('Cannot terminate an admin user.', 'error')
        return redirect(url_for('admin.manage_users'))
    
    user.current_status = 'terminated'
    db.session.commit()
    
    # Log the action
    from flask import current_app
    current_app.logger.critical(f"User {user.username} terminated by {current_user.username}")
    
    flash(f'User {user.username} has been permanently terminated.', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/reactivate_user/<int:user_id>', methods=['POST'])
@admin_required
def reactivate_user(user_id):
    """Reactivate a suspended user account"""
    user = User.query.get_or_404(user_id)
    
    if user.current_status == 'terminated':
        flash('Cannot reactivate a terminated user.', 'error')
        return redirect(url_for('admin.manage_users'))
    
    user.current_status = 'offline'
    db.session.commit()
    
    # Log the action
    from flask import current_app
    current_app.logger.info(f"User {user.username} reactivated by {current_user.username}")
    
    flash(f'User {user.username} has been reactivated.', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/reports_dashboard', methods=['GET'])
@admin_required
def manage_reports():
    # Get query parameters for filtering and sorting
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'submitted_at')
    order = request.args.get('order', 'desc')

    # Base query
    query = Report.query

    # Apply filters using the separate function
    query = apply_report_filters(query, search_query)

    # Apply sorting
    if sort_by == 'submitted_at':
        query = query.order_by(Report.submitted_at.asc() if order == 'asc' else Report.submitted_at.desc())
    elif sort_by == 'resolved_at':
        query = query.order_by(Report.resolved_at.asc() if order == 'asc' else Report.resolved_at.desc())
    else:  # Default sort by report ID
        query = query.order_by(Report.report_id.asc() if order == 'asc' else Report.report_id.desc())

    reports = query.all()

    # Calculate counts for each status
    open_reports = Report.query.filter_by(status='open').count()
    in_review_reports = Report.query.filter_by(status='in_review').count()
    action_taken_reports = Report.query.filter_by(status='action_taken').count()
    rejected_reports = Report.query.filter_by(status='rejected').count()

    return render_template(
        'oldadmin/AdminManageReports.html',
        reports=reports,
        sort_by=sort_by,
        order=order,
        search_query=search_query,
        open_reports=open_reports,
        in_review_reports=in_review_reports,
        action_taken_reports=action_taken_reports,
        rejected_reports=rejected_reports
    )

@admin_bp.route('/manage_report/<int:report_id>', methods=['GET', 'POST'])
@admin_required
def manage_report(report_id):
    report = Report.query.get(report_id)
    form = UpdateReportStatusForm()
    if not report:
        flash("Report not found.", "danger")
        return redirect(url_for('admin.manage_reports'))

    # Fetch usernames for reporter and reported user
    reporter_username = None
    if report.reporter_id:
        reporter = User.query.get(report.reporter_id)
        reporter_username = reporter.username if reporter else "Deleted User"

    reported_user = User.query.get(report.reported_user_id)
    reported_username = reported_user.username if reported_user else "Deleted User"

    if request.method == 'POST':
        new_status = request.form.get('status')
        admin_notes = request.form.get('admin_notes')
        
        if new_status in ['open', 'in_review', 'action_taken', 'rejected']:
            old_status = report.status
            report.status = new_status
            report.admin_notes = admin_notes
            report.resolved_at = datetime.utcnow() if new_status in ['action_taken', 'rejected'] else None
            
            if report.reporter_id:  # Make sure reporter exists
                # Create user-friendly status messages
                status_messages = {
                    'open': 'reopened',
                    'in_review': 'under review',
                    'action_taken': 'resolved with action taken',
                    'rejected': 'closed without action'
                }
                
                status_display = status_messages.get(new_status, new_status)
                
                notification = Notification(
                    user_id=report.reporter_id,
                    type='report_status',
                    source_id=report.report_id,
                    message=f"Your report against {reported_username} has been {status_display}.",
                    created_at=datetime.utcnow(),
                    is_read=False
                )
                
                db.session.add(notification)
            
            db.session.commit()
            flash(f"Report {report.report_id} updated from '{old_status}' to '{new_status}' and reporter notified.", "success")
        else:
            flash("Invalid status.", "danger")
        return redirect(url_for('admin.manage_reports'))

    return render_template(
        'oldadmin/AdminChangeReportStatus.html',
        report=report,
        reporter_username=reporter_username,
        reported_username=reported_username,
        form=form
    )

@admin_bp.route('/manage_ModSecLogs', methods=['GET'])
@admin_required
def admin_modsec_logs():
    # Automatically refresh logs during a GET request
    log_file_path = os.path.join(os.path.dirname(__file__), "shared_logs", "modsec_audit.log")
    parsed_logs = parse_modsec_audit_log(log_file_path)

    for log in parsed_logs:
        # Check if the log already exists to avoid duplicates
        existing_log = ModSecLog.query.filter_by(
            date=log['date'],
            time=log['time'],
            source=log['source'],
            request=log['request'],
            response=log['response'],
            attack_detected=log['attack_detected']
        ).first()
        if not existing_log:
            new_log = ModSecLog(
                date=log['date'],
                time=log['time'],
                source=log['source'],
                request=log['request'],
                response=log['response'],
                attack_detected=log['attack_detected']
            )
            db.session.add(new_log)
    db.session.commit()

    # Get query parameters for filtering and sorting
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id')  # Default sort by ID
    order = request.args.get('order', 'asc')  # Default order is ascending

    # Base query
    query = ModSecLog.query

    # Apply search filters
    if search_query:
        filters = search_query.split(',')
        for filter_item in filters:
            filter_item = filter_item.strip()
            if 'id=' in filter_item:
                try:
                    log_id = int(filter_item.split('id=')[1].strip())
                    query = query.filter(ModSecLog.id == log_id)
                except ValueError:
                    flash("Invalid ID format. Please use a number.", "danger")
            elif 'date=' in filter_item:
                date = filter_item.split('date=')[1].strip()
                query = query.filter(ModSecLog.date.ilike(f"%{date}%"))
            elif 'time=' in filter_item:
                time = filter_item.split('time=')[1].strip()
                query = query.filter(ModSecLog.time.ilike(f"%{time}%"))
            else:
                flash("Invalid query format. Please use id=, date=, or time=.", "danger")

    # Apply sorting
    if sort_by == 'date':
        query = query.order_by(ModSecLog.date.asc() if order == 'asc' else ModSecLog.date.desc())
    elif sort_by == 'time':
        query = query.order_by(ModSecLog.time.asc() if order == 'asc' else ModSecLog.time.desc())
    else:  # Default sort by ID
        query = query.order_by(ModSecLog.id.asc() if order == 'asc' else ModSecLog.id.desc())

    # Fetch logs
    logs = query.all()

    # Fetch statistics
    total_logs = ModSecLog.query.count()
    critical_attacks = ModSecLog.query.filter(ModSecLog.attack_detected.like('%Critical%')).count()
    recent_logs = ModSecLog.query.filter(ModSecLog.date >= '2025-06-01').count()

    return render_template(
        'oldadmin/AdminManageModSecLogs.html',
        logs=logs,
        total_logs=total_logs,
        critical_attacks=critical_attacks,
        recent_logs=recent_logs,
        sort_by=sort_by,
        order=order,
        search_query=search_query
    )

@admin_bp.route('/manage_ErrorLogs', methods=['GET'])
@admin_required
def admin_error_logs():
    # Automatically refresh logs during a GET request
    log_file_path = os.path.join(os.path.dirname(__file__), "shared_logs", "error.log")
    parsed_logs = parse_error_log(log_file_path)

    for log in parsed_logs:
        # Check if the log already exists to avoid duplicates
        existing_log = ErrorLog.query.filter_by(
            date=log['date'],
            time=log['time'],
            level=log['level'],
            message=log['message'],
            client_ip=log['client_ip']
        ).first()
        if not existing_log:
            new_log = ErrorLog(
                date=log['date'],
                time=log['time'],
                level=log['level'],
                message=log['message'],
                client_ip=log['client_ip']
            )
            db.session.add(new_log)
    db.session.commit()

    # Get query parameters for filtering and sorting
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id')
    order = request.args.get('order', 'asc')

    # Base query
    query = ErrorLog.query

    # Apply search filters
    if search_query:
        filters = search_query.split(',')
        for filter_item in filters:
            filter_item = filter_item.strip()
            if 'id=' in filter_item:
                try:
                    log_id = int(filter_item.split('id=')[1].strip())
                    query = query.filter(ErrorLog.id == log_id)
                except ValueError:
                    flash("Invalid ID format. Please use a number.", "danger")
            elif 'date=' in filter_item:
                date = filter_item.split('date=')[1].strip()
                query = query.filter(ErrorLog.date.ilike(f"%{date}%"))
            elif 'time=' in filter_item:
                time = filter_item.split('time=')[1].strip()
                query = query.filter(ErrorLog.time.ilike(f"%{time}%"))
            else:
                flash("Invalid query format. Please use id=, date=, or time=.", "danger")

    # Apply sorting
    if sort_by == 'date':
        query = query.order_by(ErrorLog.date.asc() if order == 'asc' else ErrorLog.date.desc())
    elif sort_by == 'time':
        query = query.order_by(ErrorLog.time.asc() if order == 'asc' else ErrorLog.time.desc())
    else:
        query = query.order_by(ErrorLog.id.asc() if order == 'asc' else ErrorLog.id.desc())

    logs = query.all()

    # Fetch statistics
    total_logs = ErrorLog.query.count()
    error_logs = ErrorLog.query.filter(ErrorLog.level == 'error').count()
    warning_logs = ErrorLog.query.filter(ErrorLog.level == 'warning').count()

    return render_template(
        'oldadmin/AdminManageErrorLogs.html',
        logs=logs,
        total_logs=total_logs,
        error_logs=error_logs,
        warning_logs=warning_logs,
        sort_by=sort_by,
        order=order,
        search_query=search_query
    )

@admin_bp.route('/manage_UserActions', methods=['GET'])
@admin_required
def admin_user_actions():
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id')
    order = request.args.get('order', 'asc')

    query = UserLog.query

    # Apply filters using the separate function
    query = apply_user_log_filters(query, search_query)

    # Apply sorting
    if sort_by == 'log_timestamp':
        query = query.order_by(UserLog.log_timestamp.asc() if order == 'asc' else UserLog.log_timestamp.desc())
    else:  # Default sort by ID
        query = query.order_by(UserLog.log_id.asc() if order == 'asc' else UserLog.log_id.desc())

    logs = query.all()
    total_logs = UserLog.query.count()
    login_attempts = UserLog.query.filter(UserLog.log_type == 'login_attempt').count()
    login_successes = UserLog.query.filter(UserLog.log_type == 'login_success').count()
    login_failures = UserLog.query.filter(UserLog.log_type == 'login_failure').count()

    return render_template(
        'oldadmin/AdminManageUserActions.html',
        logs=logs,
        total_logs=total_logs,
        login_attempts=login_attempts,
        login_successes=login_successes,
        login_failures=login_failures,
        sort_by=sort_by,
        order=order,
        search_query=search_query
    )

@admin_bp.route('/test_upload', methods=['GET', 'POST'])
@admin_required
def test_upload():
    """Testing endpoint for file upload security validation"""
    from flask import current_app
    from flask_wtf import CSRFProtect
    
    # Temporarily disable CSRF for this endpoint
    csrf = CSRFProtect()
    
    if request.method == 'POST':
        # Check if file is present
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        try:
            # Get file data
            file.seek(0)  # Reset file pointer
            file_data = file.read()
            file.seek(0)  # Reset again for potential future use
            
            # Run security validation
            result = validate_file_security(
                file_data=file_data, 
                filename=file.filename,
                max_size=10*1024*1024
            )
            
            # Display results
            if result['is_safe']:
                flash(f'✅ File "{file.filename}" passed security validation!', 'success')
                flash(f'File type: {result.get("detected_type", "Unknown")}', 'info')
                flash(f'Size: {len(file_data)} bytes', 'info')
            else:
                flash(f'❌ File "{file.filename}" failed security validation!', 'error')
                for issue in result.get('issues', []):
                    flash(f'Issue: {issue}', 'warning')
            
            # Show polyglot detection details if available
            if 'polyglot_detection' in result:
                polyglot_info = result['polyglot_detection']
                if polyglot_info.get('is_polyglot'):
                    flash('⚠️ Polyglot file detected!', 'warning')
                    for detection in polyglot_info.get('detections', []):
                        flash(f'Detection: {detection}', 'info')
        
        except Exception as e:
            flash(f'Validation error: {str(e)}', 'error')
    
    return render_template('test_upload.html')

@admin_bp.route('/content_checker', methods=['GET', 'POST'])
@admin_required
def admin_content_checker():
    """Admin-only page for testing sensitive content detection"""
    try:
        checker = SensitiveContentChecker()
        results = None
        test_text = ""
        
        if request.method == 'POST':
            test_text = request.form.get('test_text', '').strip()
            
            if test_text:
                # Check the content
                results = checker.check_content(test_text)
                
                # Log the admin test action
                admin_action = AdminAction(
                    admin_user_id=current_user.user_id,
                    action_type='content_check_test',
                    target_entity_type='system',
                    target_entity_id=None,
                    details=f"Admin {current_user.username} tested content checker with {len(test_text)} characters",
                    action_timestamp=datetime.utcnow()
                )
                db.session.add(admin_action)
                db.session.commit()
                
                if results['match_count'] > 0:
                    flash(f"⚠️ Found {results['match_count']} sensitive content matches with {results['severity']} severity.", 'warning')
                else:
                    flash("✅ No sensitive content detected.", 'success')
            else:
                flash("Please enter some text to test.", 'error')
        
        # Get pattern information for the help section
        pattern_info = checker.get_pattern_info()
        
        return render_template('admin/content_checker.html', 
                             results=results,
                             test_text=test_text,
                             pattern_info=pattern_info)
        
    except Exception as e:
        from flask import current_app
        current_app.logger.error(f"Error in admin content checker: {str(e)}")
        flash('An error occurred while testing content.', 'error')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/api/content_check', methods=['POST'])
@admin_required
def api_content_check():
    """API endpoint for content checking"""
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'No text provided'}), 400
        
        checker = SensitiveContentChecker()
        results = checker.check_content(data['text'])
        
        # Remove original_text from API response for security
        for match in results.get('matches', []):
            match.pop('original_text', None)
        
        return jsonify(results)
        
    except Exception as e:
        from flask import current_app
        current_app.logger.error(f"Error in content check API: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500