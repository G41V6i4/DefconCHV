# DefCon CHV Manager - Security Documentation

## 🔐 Admin Authentication System

### Overview
The DefCon CHV Manager now includes a secure admin authentication system with multiple layers of security protection.

### Security Features

#### 1. **Authentication & Authorization**
- Secure password hashing using Werkzeug's PBKDF2
- Session-based authentication with secure cookies
- CSRF protection for all admin forms
- Session timeout (30 minutes of inactivity)

#### 2. **Rate Limiting & IP Protection**
- Maximum 5 login attempts per IP address
- Automatic IP blocking for 30 minutes after failed attempts
- Rate limiting: 10 login attempts per minute per IP
- Global rate limits: 200 requests/day, 50 requests/hour per IP

#### 3. **Session Security**
- Secure cookie settings (HttpOnly, Secure, SameSite)
- Cryptographically secure session keys
- Session regeneration on login success
- Automatic session expiration

#### 4. **Logging & Monitoring**
- All login attempts logged with IP addresses
- Failed authentication attempts tracked
- Admin actions logged for audit trail
- Log files: `admin_access.log`

### Setup Instructions

#### 1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

#### 2. **Generate Admin Password**
```bash
python generate_admin_password.py
```

This will:
- Generate a secure random password OR let you set your own
- Create a password hash
- Provide environment variable setup instructions

#### 3. **Set Environment Variables**
```bash
# Set admin credentials
export ADMIN_USERNAME="your_admin_username"
export ADMIN_PASSWORD_HASH="generated_hash_from_script"

# Optional: Change default settings
export SESSION_TIMEOUT="1800"  # 30 minutes in seconds
```

Or create a `.env` file:
```
ADMIN_USERNAME=your_admin_username
ADMIN_PASSWORD_HASH=generated_hash_from_script
```

#### 4. **Run the Application**
```bash
python app.py
```

### Access URLs

- **Main Application**: `http://localhost:8080/`
- **Admin Login**: `http://localhost:8080/admin/login`
- **Admin Dashboard**: `http://localhost:8080/admin` (requires authentication)

### Default Credentials

⚠️ **SECURITY WARNING**: Change these immediately in production!

- **Username**: `admin`
- **Password**: `SecureAdmin2024!@#`

### Security Best Practices

#### 1. **Password Security**
- Use strong, unique passwords (minimum 12 characters)
- Include uppercase, lowercase, numbers, and special characters
- Never use default passwords in production
- Rotate passwords regularly

#### 2. **Environment Security**
- Never commit `.env` files or passwords to version control
- Use different credentials for different environments
- Store credentials securely (password managers, secure vaults)
- Limit access to credential information

#### 3. **Network Security**
- Use HTTPS in production (configure reverse proxy)
- Implement firewall rules to restrict admin access
- Consider VPN access for admin interfaces
- Monitor network traffic for suspicious patterns

#### 4. **System Security**
- Keep system and dependencies updated
- Run with minimal privileges
- Enable system-level logging
- Regular security audits

### Production Deployment

#### 1. **HTTPS Configuration**
```bash
# Example with nginx reverse proxy
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 2. **Redis for Session Storage** (Recommended)
```python
# In production, use Redis for better performance
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379')
```

#### 3. **Environment Variables**
```bash
# Production environment
export FLASK_ENV=production
export ADMIN_USERNAME="secure_admin_user"
export ADMIN_PASSWORD_HASH="secure_hash_here"
export SESSION_TIMEOUT="900"  # 15 minutes for production
```

### Security Monitoring

#### 1. **Log Analysis**
Monitor these log patterns:
```bash
# Failed login attempts
grep "Failed login attempt" admin_access.log

# IP blocking events
grep "Blocked IP" admin_access.log

# Successful logins
grep "Successful admin login" admin_access.log
```

#### 2. **Automated Monitoring**
```bash
# Example logwatch configuration
# Monitor for repeated failed attempts
tail -f admin_access.log | grep "Failed login attempt" | while read line; do
    echo "Security Alert: $line" | mail -s "Admin Login Failure" admin@company.com
done
```

### Troubleshooting

#### 1. **Locked Out (IP Blocked)**
- Wait 30 minutes for automatic unblock
- Or restart the application to reset failed attempt counters
- Check logs for the blocking reason

#### 2. **Session Issues**
- Clear browser cookies
- Check system time synchronization
- Verify session timeout settings

#### 3. **CSRF Token Errors**
- Ensure JavaScript is enabled
- Clear browser cache
- Check for multiple browser tabs

### Security Incident Response

#### 1. **Suspected Breach**
1. Immediately change admin passwords
2. Review access logs for suspicious activity
3. Check system logs for unauthorized changes
4. Consider temporary service shutdown

#### 2. **Password Compromise**
1. Generate new password hash: `python generate_admin_password.py`
2. Update environment variables
3. Restart application
4. Monitor logs for unauthorized access attempts

### Contact & Support

For security issues or questions:
- Review logs in `admin_access.log`
- Check system configuration
- Verify environment variables
- Test with curl/wget for API endpoints

Remember: Security is an ongoing process, not a one-time setup!