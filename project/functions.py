from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user
from datetime import datetime
import os

# Import your models and other dependencies
from decorators import admin_required
from forms import UpdateUserStatusForm, UpdateReportStatusForm
from filters import apply_user_filters, apply_user_sorting, apply_report_filters, apply_user_log_filters
from parse_test import parse_modsec_audit_log, parse_error_log
from file_validate import validate_file_security
from datetime import datetime, timedelta
# Models
from models import (
    db, User, Role, Permission, Event, EventParticipant, Post, PostImage, PostLike,
    Notification, Report, Chat, ChatParticipant, Message, 
    Friendship, AdminAction, UserLog, ModSecLog, ErrorLog, 
    WebAuthnCredential, user_role_assignments,Event,FriendChatMap,BlockedUser,UserPublicKey, ChatKeyEnvelope


)

# Helper function for relative time
def get_relative_time(post_date):
    from datetime import datetime, timezone
    import math
    
    now = datetime.now(timezone.utc)
    if post_date.tzinfo is None:
        post_date = post_date.replace(tzinfo=timezone.utc)
    
    diff = now - post_date
    
    if diff.days > 0:
        if diff.days == 1:
            return "1 day ago"
        elif diff.days < 7:
            return f"{diff.days} days ago"
        elif diff.days < 30:
            weeks = diff.days // 7
            return f"{weeks} week{'s' if weeks > 1 else ''} ago"
        else:
            months = diff.days // 30
            return f"{months} month{'s' if months > 1 else ''} ago"
    
    hours = diff.seconds // 3600
    if hours > 0:
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    
    minutes = diff.seconds // 60
    if minutes > 0:
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    
    return "Just now"

# b64 encode all
import base64
def b64encode_all(data, _seen=None):
    """Recursively encode all bytes objects in a data structure to base64 strings with recursion protection"""
    if _seen is None:
        _seen = set()
    
    # Prevent infinite recursion by tracking objects we've already seen
    obj_id = id(data)
    if obj_id in _seen:
        return str(data)  # Return string representation if we've seen this object before
    
    if isinstance(data, bytes):
        return base64.b64encode(data).decode('utf-8')
    elif isinstance(data, dict):
        _seen.add(obj_id)
        result = {}
        try:
            for key, value in data.items():
                result[key] = b64encode_all(value, _seen)
        finally:
            _seen.discard(obj_id)
        return result
    elif isinstance(data, list):
        _seen.add(obj_id)
        result = []
        try:
            for item in data:
                result.append(b64encode_all(item, _seen))
        finally:
            _seen.discard(obj_id)
        return result
    elif hasattr(data, 'value') and not isinstance(data, type):
        # Handle enum-like objects
        try:
            return str(data.value)
        except:
            return str(data)
    elif hasattr(data, '__dict__') and not isinstance(data, type):
        # Handle objects with attributes, but with recursion protection
        _seen.add(obj_id)
        try:
            obj_dict = {}
            # Limit the attributes we process to avoid complex internal objects
            safe_attrs = []
            for attr_name in dir(data):
                if (not attr_name.startswith('_') and 
                    not callable(getattr(data, attr_name, None)) and
                    attr_name not in ['__class__', '__module__', '__dict__', '__weakref__']):
                    safe_attrs.append(attr_name)
                    if len(safe_attrs) > 20:  # Limit to prevent excessive processing
                        break
            
            for attr_name in safe_attrs:
                try:
                    attr_value = getattr(data, attr_name)
                    obj_dict[attr_name] = b64encode_all(attr_value, _seen)
                except Exception:
                    # Skip attributes that can't be accessed or converted
                    continue
            return obj_dict
        except Exception:
            return str(data)
        finally:
            _seen.discard(obj_id)
    else:
        return data
#fido2 server
def get_fido2_server():
    from flask import request
    rp_id = request.host.split(':')[0]
    rp_name = "SimpleBook"
    rp = PublicKeyCredentialRpEntity(rp_id, rp_name)
    return Fido2Server(rp)


#event reminder helper
def send_user_event_reminders(user_id):
    """Send event reminder notifications to a specific user for events happening in the next 24 hours"""
    try:
        # Get events happening in the next 24 hours
        now = datetime.utcnow()
        next_24_hours = now + timedelta(hours=24)
        
        # Find events user created that are happening in next 24 hours
        user_created_events = Event.query.filter(
            Event.user_id == user_id,
            Event.event_datetime >= now,
            Event.event_datetime <= next_24_hours,
            Event.is_reminder == False
        ).all()
        
        # Find events user joined that are happening in next 24 hours
        user_joined_events = (
            db.session.query(Event)
            .join(EventParticipant, Event.event_id == EventParticipant.event_id)
            .filter(
                EventParticipant.user_id == user_id,
                EventParticipant.status == 'joined',
                Event.event_datetime >= now,
                Event.event_datetime <= next_24_hours,
                Event.is_reminder == False
            )
            .all()
        )
        
        # Send reminders for events user created
        for event in user_created_events:
            # Check if reminder already exists
            existing_notif = Notification.query.filter_by(
                user_id=user_id,
                type='event_notification',
                source_id=event.event_id
            ).filter(
                Notification.message.like(f"%Your event '{event.title}' is happening%"),
                Notification.created_at >= now - timedelta(hours=1) 
            ).first()
            
            if not existing_notif:
                hours_until = int((event.event_datetime - now).total_seconds() / 3600)
                if hours_until <= 1:
                    time_msg = "very soon"
                elif hours_until <= 6:
                    time_msg = f"in {hours_until} hours"
                else:
                    time_msg = "within 24 hours"
                
                notification = Notification(
                    user_id=user_id,
                    type='event_notification',
                    source_id=event.event_id,
                    message=f"Reminder: Your event '{event.title}' is happening {time_msg}!",
                    created_at=datetime.utcnow(),
                    is_read=False
                )
                db.session.add(notification)
        
        # Send reminders for events user joined
        for event in user_joined_events:
            # Check if reminder already exists
            existing_notif = Notification.query.filter_by(
                user_id=user_id,
                type='event_notification',
                source_id=event.event_id
            ).filter(
                Notification.message.like(f"%'{event.title}' you joined is happening%"),
                Notification.created_at >= now - timedelta(hours=1)  # Don't spam
            ).first()
            
            if not existing_notif:
                hours_until = int((event.event_datetime - now).total_seconds() / 3600)
                if hours_until <= 1:
                    time_msg = "very soon"
                elif hours_until <= 6:
                    time_msg = f"in {hours_until} hours"
                else:
                    time_msg = "within 24 hours"
                
                notification = Notification(
                    user_id=user_id,
                    type='event_notification',
                    source_id=event.event_id,
                    message=f"Reminder: '{event.title}' you joined is happening {time_msg}!",
                    created_at=datetime.utcnow(),
                    is_read=False
                )
                db.session.add(notification)
        
        db.session.commit()
        
    except Exception as e:
        print(f"Error sending user event reminders: {e}")
        db.session.rollback()