from werkzeug.security import generate_password_hash

print("Admin Pass Hash:", generate_password_hash("adminpass"))
print("Editor Pass Hash:", generate_password_hash("editorpass"))
print("User Pass Hash:", generate_password_hash("userpass"))