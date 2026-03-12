import os
import logging
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError 
import pymysql

# Configuración de logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- CONFIGURACIÓN DE LA BD (CORREGIDA PARA RAILWAY) ---
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Ajuste automático de protocolo para Railway/Nube
    if database_url.startswith("mysql://"):
        database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.logger.info("Conectado a la base de datos de Railway")
else:
    # Configuración para desarrollo local
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/SISTEMA'
    app.logger.warning("DATABASE_URL no detectada. Usando localhost.")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mi_clave_secreta_y_segura_para_sistema_tickets' 

db = SQLAlchemy(app)

# --- CONFIGURACIÓN DE LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- CARPETA DE SUBIDAS ---
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------------- VARIABLES GLOBALES ----------------------
ROLES_DISPONIBLES = ['Admin', 'Tecnico', 'Usuario'] 

# --- FUNCIONES ÚTILES ---
def guardar_foto(file):
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        unique_filename = f"{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        try:
            file.save(filepath)
            if os.path.getsize(filepath) == 0:
                os.remove(filepath)
                return None
            return os.path.join('uploads', unique_filename).replace('\\', '/')
        except Exception as e:
            app.logger.error(f"Error al guardar archivo: {e}")
            return None
    return None

@login_manager.user_loader
def load_user(user_id):
    # Uso de db.session.get para mayor compatibilidad
    return db.session.get(User, int(user_id))

@app.context_processor
def inject_now():
    return {'now': datetime.datetime.utcnow}

# --- MODELOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    sector = db.Column(db.String(50))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class EquipoReporte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sector = db.Column(db.String(50), nullable=False)
    inventario_numero = db.Column(db.String(50), nullable=False)
    falla_descripcion = db.Column(db.Text, nullable=False)
    estado = db.Column(db.String(20), default='Pendiente')
    fecha_reporte = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    fecha_reparacion = db.Column(db.DateTime, nullable=True)
    foto_falla_path = db.Column(db.String(255), nullable=True)
    foto_reparado_path = db.Column(db.String(255), nullable=True)
    user = db.relationship('User', backref=db.backref('equipo_reportes', lazy=True))

class PatrullaReporte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    unidad_numero = db.Column(db.String(50), nullable=False)
    sector = db.Column(db.String(50), nullable=False)
    oficial_nombre = db.Column(db.String(100), nullable=False) 
    placa = db.Column(db.String(20), nullable=False)
    marca = db.Column(db.String(50), nullable=False)
    modelo = db.Column(db.String(50), nullable=False)
    turno = db.Column(db.String(20), nullable=False)
    camara1_funciona = db.Column(db.Boolean, default=True)
    camara2_funciona = db.Column(db.Boolean, default=True)
    camara3_funciona = db.Column(db.Boolean, default=True)
    camara4_funciona = db.Column(db.Boolean, default=True)
    grabadora1_funciona = db.Column(db.Boolean, default=True)
    grabadora2_funciona = db.Column(db.Boolean, default=True)
    grabadora3_funciona = db.Column(db.Boolean, default=True)
    grabadora4_funciona = db.Column(db.Boolean, default=True)
    falla_camara_desc_1 = db.Column(db.Text, nullable=True) 
    falla_camara_foto_1 = db.Column(db.String(255), nullable=True) 
    falla_camara_desc_2 = db.Column(db.Text, nullable=True) 
    falla_camara_foto_2 = db.Column(db.String(255), nullable=True) 
    falla_camara_desc_3 = db.Column(db.Text, nullable=True) 
    falla_camara_foto_3 = db.Column(db.String(255), nullable=True) 
    falla_camara_desc_4 = db.Column(db.Text, nullable=True) 
    falla_camara_foto_4 = db.Column(db.String(255), nullable=True) 
    falla_grabadora_desc_1 = db.Column(db.Text, nullable=True) 
    falla_grabadora_foto_1 = db.Column(db.String(255), nullable=True) 
    falla_grabadora_desc_2 = db.Column(db.Text, nullable=True) 
    falla_grabadora_foto_2 = db.Column(db.String(255), nullable=True) 
    falla_grabadora_desc_3 = db.Column(db.Text, nullable=True) 
    falla_grabadora_foto_3 = db.Column(db.String(255), nullable=True) 
    falla_grabadora_desc_4 = db.Column(db.Text, nullable=True) 
    falla_grabadora_foto_4 = db.Column(db.String(255), nullable=True) 
    observaciones = db.Column(db.Text, nullable=True)
    falla_descripcion = db.Column(db.Text, nullable=True)
    estado = db.Column(db.String(20), default='Pendiente')
    fecha_reporte = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    fecha_reparacion = db.Column(db.DateTime, nullable=True)
    foto_falla_path = db.Column(db.String(255), nullable=True)
    foto_reparado_path = db.Column(db.String(255), nullable=True)
    user = db.relationship('User', backref=db.backref('patrulla_reportes', lazy=True))

# --------------------- RUTAS ------------------------

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Credenciales inválidas', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Admin':
        return redirect(url_for('admin_dashboard'))
    if current_user.role == 'Tecnico':
        return redirect(url_for('tecnico_dashboard'))
    return redirect(url_for('oficial_dashboard'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('admin_dashboard.html', user=current_user)

@app.route('/admin/usuarios', methods=['GET', 'POST'])
@login_required
def admin_usuarios():
    if current_user.role != 'Admin':
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        sector = request.form.get('sector', '').strip()
        
        try:
            nuevo_usuario = User(username=username, role=role, sector=sector if sector else None)
            nuevo_usuario.set_password(password)
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash(f'Usuario "{username}" creado exitosamente.', 'success')
            return redirect(url_for('admin_usuarios')) 
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al crear usuario: {e}")
            flash('Error al crear el usuario.', 'danger')

    usuarios = User.query.order_by(User.username).all()
    return render_template('admin_usuarios.html', user=current_user, usuarios=usuarios, roles=ROLES_DISPONIBLES)

# --- DASHBOARD TECNICO ---
@app.route('/tecnico/dashboard')
@login_required
def tecnico_dashboard():
    if current_user.role != 'Tecnico':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))

    base_query_equipo = EquipoReporte.query.filter(EquipoReporte.estado.in_(['Pendiente', 'En Progreso']))
    base_query_patrulla = PatrullaReporte.query.filter(PatrullaReporte.estado.in_(['Pendiente', 'En Progreso']))
    
    sector_filtro = current_user.sector
    app.logger.info(f"Técnico: {current_user.username}, Sector: '{sector_filtro}'")

    if sector_filtro and sector_filtro != 'Global':
        base_query_equipo = base_query_equipo.filter_by(sector=sector_filtro)
        base_query_patrulla = base_query_patrulla.filter_by(sector=sector_filtro)

    pendientes_equipo = base_query_equipo.order_by(EquipoReporte.fecha_reporte.asc()).all()
    pendientes_patrulla = base_query_patrulla.order_by(PatrullaReporte.fecha_reporte.asc()).all()
    
    return render_template('tecnico_dashboard.html', user=current_user, 
                           pendientes_equipo=pendientes_equipo, pendientes_patrulla=pendientes_patrulla)

# (Siguen el resto de rutas de tu archivo original con app.logger...)
# NOTA: Asegúrate de cambiar todos los current_app.logger por app.logger en las funciones que faltan.

def crear_admin_inicial():
    with app.app_context():
        db.create_all() 
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='Admin', sector='Administracion Central')
            admin.set_password('adminpass')
            db.session.add(admin)
            db.session.commit()
            print("ADMIN CREADO -> usuario: admin  pass: adminpass")

if __name__ == '__main__':
    crear_admin_inicial()
    app.run(debug=True)