from werkzeug.security import generate_password_hash
from app import db, User

admin = User.query.filter_by(username='admin').first()

if admin:
    admin.password_hash = generate_password_hash("adminpass")
    db.session.commit()
    print("Contraseña del admin restablecida correctamente.")
else:
    print("No existe el usuario admin.")
