import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, current_app, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError 
import pymysql
import logging 

# Configuración de la aplicación
app = Flask(__name__)

# --- CONFIGURACIÓN DE LA BD ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/SISTEMA'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'mi_clave_secreta_y_segura_para_sistema_tickets' 

db = SQLAlchemy(app)

# --- LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Carpeta de fotos
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------- VARIABLES GLOBALES (ROLES) ----------------------
ROLES_DISPONIBLES = ['Admin', 'Tecnico', 'Usuario'] 


# --- FUNCIONES ÚTILES ---
def guardar_foto(file):
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        # Generar un nombre de archivo único basado en la fecha y hora
        unique_filename = f"{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        try:
            file.save(filepath)
            if os.path.getsize(filepath) == 0:
                os.remove(filepath)
                return None
            return os.path.join('uploads', unique_filename).replace('\\', '/')
        except Exception as e:
            current_app.logger.error(f"Error al guardar archivo: {e}")
            return None
    return None 


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
    
    # ------------------ CAMPOS DE INFORMACIÓN BÁSICA ------------------
    oficial_nombre = db.Column(db.String(100), nullable=False) 
    placa = db.Column(db.String(20), nullable=False)
    marca = db.Column(db.String(50), nullable=False)
    modelo = db.Column(db.String(50), nullable=False)
    turno = db.Column(db.String(20), nullable=False)
    
    # ------------------ ESTADO DE CÁMARAS Y GRABADORAS ------------------
    camara1_funciona = db.Column(db.Boolean, default=True)
    camara2_funciona = db.Column(db.Boolean, default=True)
    camara3_funciona = db.Column(db.Boolean, default=True)
    camara4_funciona = db.Column(db.Boolean, default=True)
    
    grabadora1_funciona = db.Column(db.Boolean, default=True)
    grabadora2_funciona = db.Column(db.Boolean, default=True)
    grabadora3_funciona = db.Column(db.Boolean, default=True)
    grabadora4_funciona = db.Column(db.Boolean, default=True)

    # ------------------ DESCRIPCIONES Y EVIDENCIAS DE FALLAS ------------------
    # Fallas de Cámara
    falla_camara_desc_1 = db.Column(db.Text, nullable=True) 
    falla_camara_foto_1 = db.Column(db.String(255), nullable=True) 
    falla_camara_desc_2 = db.Column(db.Text, nullable=True) 
    falla_camara_foto_2 = db.Column(db.String(255), nullable=True) 
    falla_camara_desc_3 = db.Column(db.Text, nullable=True) 
    falla_camara_foto_3 = db.Column(db.String(255), nullable=True) 
    falla_camara_desc_4 = db.Column(db.Text, nullable=True) 
    falla_camara_foto_4 = db.Column(db.String(255), nullable=True) 

    # Fallas de Grabadora
    falla_grabadora_desc_1 = db.Column(db.Text, nullable=True) 
    falla_grabadora_foto_1 = db.Column(db.String(255), nullable=True) 
    falla_grabadora_desc_2 = db.Column(db.Text, nullable=True) 
    falla_grabadora_foto_2 = db.Column(db.String(255), nullable=True) 
    falla_grabadora_desc_3 = db.Column(db.Text, nullable=True) 
    falla_grabadora_foto_3 = db.Column(db.String(255), nullable=True) 
    falla_grabadora_desc_4 = db.Column(db.Text, nullable=True) 
    falla_grabadora_foto_4 = db.Column(db.String(255), nullable=True) 

    # Observaciones generales
    observaciones = db.Column(db.Text, nullable=True)
    
    # ------------------ CAMPOS DE GESTIÓN ------------------
    falla_descripcion = db.Column(db.Text, nullable=True)
    estado = db.Column(db.String(20), default='Pendiente')
    fecha_reporte = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    fecha_reparacion = db.Column(db.DateTime, nullable=True)
    foto_falla_path = db.Column(db.String(255), nullable=True)
    foto_reparado_path = db.Column(db.String(255), nullable=True)

    user = db.relationship('User', backref=db.backref('patrulla_reportes', lazy=True))


# --------------------- RUTAS BÁSICAS ------------------------

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
        return redirect(url_for('login'))

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


# ---------------------- DASHBOARD ADMIN ----------------------

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('admin_dashboard.html', user=current_user)


# ---------------------- ADMIN USUARIOS ----------------------

@app.route('/admin/usuarios', methods=['GET', 'POST'])
@login_required
def admin_usuarios():
    if current_user.role != 'Admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))
    
    # Lógica de CREACIÓN (POST)
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        sector = request.form.get('sector', '').strip()
        
        # Validaciones
        if not username or not password or not role:
            flash('Usuario, contraseña y rol son obligatorios.', 'danger')
            usuarios = User.query.order_by(User.username).all()
            return render_template('admin_usuarios.html', user=current_user, usuarios=usuarios, roles=ROLES_DISPONIBLES)

        usuario_existente = User.query.filter_by(username=username).first()
        if usuario_existente:
            flash('El nombre de usuario ya existe.', 'danger')
            usuarios = User.query.order_by(User.username).all()
            return render_template('admin_usuarios.html', user=current_user, usuarios=usuarios, roles=ROLES_DISPONIBLES)
        
        try:
            nuevo_usuario = User(
                username=username,
                role=role,
                sector=sector if sector else None
            )
            nuevo_usuario.set_password(password)
            
            db.session.add(nuevo_usuario)
            db.session.commit()
            
            flash(f'Usuario "{username}" creado exitosamente.', 'success')
            return redirect(url_for('admin_usuarios')) 
            
        except Exception as e:
            db.session.rollback()
            flash('Error al crear el usuario.', 'danger')
            current_app.logger.error(f"Error al crear usuario: {e}")

    # Lógica de VISUALIZACIÓN (GET)
    usuarios = User.query.order_by(User.username).all()
    
    return render_template('admin_usuarios.html', 
                           user=current_user, 
                           usuarios=usuarios,
                           roles=ROLES_DISPONIBLES)


@app.route('/admin/usuarios/editar/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_editar_usuario(user_id):
    if current_user.role != 'Admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))
    
    usuario = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        role = request.form.get('role', '').strip()
        sector = request.form.get('sector', '').strip()
        nueva_password = request.form.get('password', '').strip()
        
        if not username or not role:
            flash('Usuario y rol son obligatorios.', 'danger')
            return render_template('admin_editar_usuario.html', user=current_user, usuario=usuario, roles=ROLES_DISPONIBLES)
        
        usuario_existente = User.query.filter_by(username=username).first()
        if usuario_existente and usuario_existente.id != user_id:
            flash('El nombre de usuario ya existe.', 'danger')
            return render_template('admin_editar_usuario.html', user=current_user, usuario=usuario, roles=ROLES_DISPONIBLES)
        
        try:
            usuario.username = username
            usuario.role = role
            usuario.sector = sector if sector else None
            
            if nueva_password:
                usuario.set_password(nueva_password)
            
            db.session.commit()
            
            flash(f'Usuario "{username}" actualizado exitosamente.', 'success')
            return redirect(url_for('admin_usuarios'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error al actualizar el usuario.', 'danger')
            current_app.logger.error(f"Error al editar usuario: {e}")
    
    return render_template('admin_editar_usuario.html', 
                           user=current_user, 
                           usuario=usuario, 
                           roles=ROLES_DISPONIBLES)


@app.route('/admin/usuarios/eliminar/<int:user_id>', methods=['POST'])
@login_required
def admin_eliminar_usuario(user_id):
    if current_user.role != 'Admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))
    
    if user_id == current_user.id:
        flash('No puedes eliminar tu propio usuario.', 'danger')
        return redirect(url_for('admin_usuarios'))
    
    usuario = User.query.get_or_404(user_id)
    
    try:
        db.session.delete(usuario)
        db.session.commit()
        
        flash(f'Usuario "{usuario.username}" eliminado exitosamente.', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash('Error al eliminar el usuario.', 'danger')
        current_app.logger.error(f"Error al eliminar usuario: {e}")
    
    return redirect(url_for('admin_usuarios'))


# ---------------------- DASHBOARD OFICIAL ----------------------

@app.route('/oficial/dashboard')
@login_required
def oficial_dashboard():
    if current_user.role != 'Usuario': 
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))
    return render_template('usuario_dashboard.html', user=current_user)


# ---------------------- DASHBOARD TECNICO ----------------------

@app.route('/tecnico/dashboard')
@login_required
def tecnico_dashboard():
    if current_user.role != 'Tecnico':
        flash("Acceso denegado. Rol incorrecto.", "danger")
        return redirect(url_for('dashboard'))

    base_query_equipo = EquipoReporte.query.filter(
        EquipoReporte.estado.in_(['Pendiente', 'En Progreso'])
    )
    
    base_query_patrulla = PatrullaReporte.query.filter(
        PatrullaReporte.estado.in_(['Pendiente', 'En Progreso'])
    )
    
    sector_filtro = current_user.sector
    
    current_app.logger.info(f"--- Diagnóstico Técnico Dashboard ---")
    current_app.logger.info(f"Técnico: {current_user.username}, Sector: '{sector_filtro}'")

    if sector_filtro and sector_filtro != 'Global':
        current_app.logger.info(f"Aplicando filtro por sector: '{sector_filtro}'")
        base_query_equipo = base_query_equipo.filter_by(sector=sector_filtro)
        base_query_patrulla = base_query_patrulla.filter_by(sector=sector_filtro)
    else:
        current_app.logger.info("El técnico es 'Global' o su sector es nulo. Se mostrarán todos los sectores.")

    pendientes_equipo = base_query_equipo.order_by(EquipoReporte.fecha_reporte.asc()).all()
    pendientes_patrulla = base_query_patrulla.order_by(PatrullaReporte.fecha_reporte.asc()).all()
    
    current_app.logger.info(f"Resultados: Equipos: {len(pendientes_equipo)}, Patrullas: {len(pendientes_patrulla)}")

    return render_template('tecnico_dashboard.html', 
                           user=current_user, 
                           pendientes_equipo=pendientes_equipo,
                           pendientes_patrulla=pendientes_patrulla)


# ---------------------- REPORTE EQUIPO ----------------------

@app.route('/reporte_equipo', methods=['GET', 'POST'])
@login_required
def reporte_equipo_form():
    if request.method == 'POST':
        tipo = request.form.get('tipo', '').strip()
        serie = request.form.get('serie', '').strip()
        estado_form = request.form.get('estado', '').strip()
        comentarios = request.form.get('comentarios', '').strip()
        
        if not tipo or not serie or not estado_form:
            flash("Todos los campos marcados con (*) son obligatorios.", "danger")
            return render_template('reporte_equipo_form.html') 

        if estado_form in ['falla_menor', 'falla_grave', 'mantenimiento'] and not comentarios:
            flash("Si el estado es una falla o mantenimiento, debes describir el problema.", "danger")
            return render_template('reporte_equipo_form.html') 

        if estado_form == 'operativo':
            flash("Equipo registrado como operativo. No se generó ticket de soporte.", "info")
            return redirect(url_for('oficial_dashboard'))

        try:
            nuevo_reporte = EquipoReporte(
                user_id=current_user.id,
                sector=current_user.sector or 'Sin Sector',
                inventario_numero=serie,
                falla_descripcion=f"[{tipo}]\n\n{comentarios}",
                estado='Pendiente',
                fecha_reporte=datetime.datetime.utcnow()
            )
            
            db.session.add(nuevo_reporte)
            db.session.commit()

            flash("✓ Reporte enviado correctamente. El equipo técnico lo revisará pronto.", "success")
            return redirect(url_for('oficial_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash("Error al guardar el reporte. Contacta al administrador.", "danger")
            current_app.logger.error(f"Error al guardar reporte de equipo: {e}")
            return render_template('reporte_equipo_form.html')

    return render_template('reporte_equipo_form.html')


# ---------------------- REPORTE PATRULLA ----------------------

@app.route('/reporte/patrulla', methods=['GET', 'POST'])
@login_required
def reporte_patrulla_form():
    if current_user.role != 'Usuario':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            unidad_numero = request.form.get('unidad_numero', '').strip()
            oficial_nombre = request.form.get('oficial_nombre', '').strip()
            placa = request.form.get('placa', '').strip()
            marca = request.form.get('marca', '').strip()
            modelo = request.form.get('modelo', '').strip()
            turno = request.form.get('turno', '').strip()
            fecha_reporte_str = request.form.get('fecha_reporte')
            
            if not all([unidad_numero, oficial_nombre, placa, marca, modelo, turno, fecha_reporte_str]):
                flash('Faltan campos obligatorios en la información de la unidad.', 'danger')
                return render_template('reporte_patrulla_form.html', user=current_user)

            try:
                fecha_reporte = datetime.datetime.fromisoformat(fecha_reporte_str) 
            except ValueError:
                flash('Error en el formato de Fecha y Hora del Reporte.', 'danger')
                return render_template('reporte_patrulla_form.html', user=current_user)

            todas_ok = True
            falla_lista = []
            componentes_status = {}
            componentes_detalle = {}
            primera_foto_global = None

            for i in range(1, 5):
                # CAMARAS
                cam_funciona = request.form.get(f'camara_{i}') == '1'
                componentes_status[f'camara{i}_funciona'] = cam_funciona
                
                if not cam_funciona:
                    todas_ok = False
                    detalle = request.form.get(f'falla_camara_desc_{i}', '').strip()
                    foto = request.files.get(f'falla_camara_foto_{i}')
                    
                    falla_lista.append(f"[Cámara {i} - Falla]: {detalle}")
                    
                    componentes_detalle[f'falla_camara_desc_{i}'] = detalle
                    p = guardar_foto(foto)
                    componentes_detalle[f'falla_camara_foto_{i}'] = p
                    if p and primera_foto_global is None:
                        primera_foto_global = p

                # GRABADORAS
                grab_funciona = request.form.get(f'grabadora_{i}') == '1'
                componentes_status[f'grabadora{i}_funciona'] = grab_funciona

                if not grab_funciona:
                    todas_ok = False
                    detalle = request.form.get(f'falla_grabadora_desc_{i}', '').strip()
                    foto = request.files.get(f'falla_grabadora_foto_{i}')
                    
                    falla_lista.append(f"[Grabadora {i} - Falla]: {detalle}")
                    
                    componentes_detalle[f'falla_grabadora_desc_{i}'] = detalle
                    p = guardar_foto(foto)
                    componentes_detalle[f'falla_grabadora_foto_{i}'] = p
                    if p and primera_foto_global is None:
                        primera_foto_global = p
            
            observaciones = request.form.get('observaciones', '').strip()
            if observaciones:
                falla_lista.append(f"[Observaciones Adicionales]: {observaciones}")

            falla_final = '\n'.join(falla_lista)
            estado = "Pendiente" if not todas_ok else "Cerrado" 

            nuevo = PatrullaReporte(
                user_id=current_user.id,
                unidad_numero=unidad_numero,
                sector=current_user.sector,
                oficial_nombre=oficial_nombre,
                placa=placa,
                marca=marca,        
                modelo=modelo,      
                turno=turno,        
                fecha_reporte=fecha_reporte,
                **componentes_status,
                **componentes_detalle,
                observaciones=observaciones,
                falla_descripcion=falla_final,
                estado=estado,
                foto_falla_path=primera_foto_global
            )
            
            if estado == 'Cerrado':
                nuevo.fecha_reparacion = datetime.datetime.utcnow()
                
            db.session.add(nuevo)
            db.session.commit()
            
            if estado == 'Cerrado':
                flash("Reporte enviado. Patrulla registrada como operativa y reporte cerrado.", "success")
            else:
                flash("Reporte de falla enviado. El equipo técnico lo revisará.", "warning")
                
            return redirect(url_for('mis_reportes'))

        except ValueError as ve:
            flash(f'Error de datos: {ve}', 'danger')
            current_app.logger.error(f"Error de valor en reporte de patrulla: {ve}")
            return render_template('reporte_patrulla_form.html', user=current_user)

        except Exception as e:
            db.session.rollback()
            flash("Error al guardar reporte. Contacta al administrador.", "danger")
            current_app.logger.error(f"Error fatal al guardar reporte de patrulla: {e}")
            return render_template('reporte_patrulla_form.html', user=current_user)

    return render_template('reporte_patrulla_form.html', user=current_user)


# ---------------------- MIS REPORTES ----------------------

@app.route('/mis_reportes')
@login_required
def mis_reportes():
    if current_user.role != 'Usuario':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('dashboard'))

    equipos = EquipoReporte.query.filter_by(user_id=current_user.id).order_by(EquipoReporte.fecha_reporte.desc()).all()
    patrullas = PatrullaReporte.query.filter_by(user_id=current_user.id).order_by(PatrullaReporte.fecha_reporte.desc()).all()

    return render_template('mis_reportes.html', user=current_user,
                           equipos=equipos, patrullas=patrullas)


# ---------------------- EDITAR REPORTE DE EQUIPO (TEC/ADMIN) ----------------------

@app.route('/reporte/equipo/editar/<int:reporte_id>', methods=['GET', 'POST'])
@login_required
def editar_reporte_equipo(reporte_id):
    if current_user.role not in ['Admin', 'Tecnico']:
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))

    reporte = EquipoReporte.query.get_or_404(reporte_id)

    if current_user.role == 'Tecnico' and current_user.sector != 'Global' and reporte.sector != current_user.sector:
        flash("No pertenece a su sector.", "danger")
        return redirect(url_for('tecnico_dashboard'))

    if request.method == 'POST':
        if current_user.role == 'Admin':
            reporte.inventario_numero = request.form.get('inventario', reporte.inventario_numero).strip()
            reporte.falla_descripcion = request.form.get('falla', reporte.falla_descripcion).strip()
            reporte.sector = request.form.get('sector', reporte.sector).strip()

        nuevo_estado = request.form.get('estado')
        reporte.estado = nuevo_estado

        foto_rep = request.files.get('foto_reparado')
        if foto_rep and foto_rep.filename:
            p = guardar_foto(foto_rep)
            if p:
                reporte.foto_reparado_path = p

        if nuevo_estado in ['Reparado', 'Finalizado', 'Cerrado'] and reporte.fecha_reparacion is None:
            reporte.fecha_reparacion = datetime.datetime.utcnow()
        elif nuevo_estado in ['Pendiente', 'En Progreso']:
            reporte.fecha_reparacion = None

        try:
            db.session.commit()
            flash("Reporte actualizado.", "success")

            if current_user.role == 'Admin':
                return redirect(url_for('admin_ver_equipos'))
            return redirect(url_for('tecnico_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash("Error al actualizar.", "danger")
            current_app.logger.error(f"Error al editar equipo: {e}")

    return render_template('editar_reporte_equipo.html',
                           reporte=reporte,
                           user=current_user,
                           roles_edicion=['Pendiente', 'En Progreso', 'Reparado', 'Cerrado'])


# ---------------------- EDITAR REPORTE DE PATRULLA (TEC/ADMIN) ----------------------

@app.route('/reporte/patrulla/editar/<int:reporte_id>', methods=['GET', 'POST'])
@login_required
def editar_reporte_patrulla(reporte_id):
    if current_user.role not in ['Admin', 'Tecnico']:
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))

    reporte = PatrullaReporte.query.get_or_404(reporte_id)

    if current_user.role == 'Tecnico' and current_user.sector != 'Global' and reporte.sector != current_user.sector:
        flash("No tienes permiso para gestionar reportes fuera de tu sector.", "danger")
        return redirect(url_for('tecnico_dashboard'))

    if request.method == 'POST':
        foto_rep = request.files.get('foto_reparado')
        if foto_rep and foto_rep.filename:
            p = guardar_foto(foto_rep)
            if p:
                reporte.foto_reparado_path = p
        
        try:
            reporte.estado = 'Reparado'
            if reporte.fecha_reparacion is None:
                reporte.fecha_reparacion = datetime.datetime.utcnow()
            
            db.session.commit()
            
            flash(f"Reporte de Patrulla #{reporte.id} actualizado a REPARADO.", "success")
            
            if current_user.role == 'Admin':
                return redirect(url_for('admin_ver_patrullas'))
            return redirect(url_for('tecnico_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash("Error al actualizar el reporte.", "danger")
            current_app.logger.error(f"Error al editar reporte de patrulla: {e}")
            return redirect(url_for('editar_reporte_patrulla', reporte_id=reporte.id))

    return render_template('editar_reporte_patrulla.html', reporte=reporte, user=current_user)


# ---------------------- CAMBIAR ESTADO DE REPORTE DE PATRULLA ----------------------

@app.route('/admin/reportes/patrulla/<int:reporte_id>/estado', methods=['POST'])
@login_required
def cambiar_estado_reporte_patrulla(reporte_id):
    if current_user.role != 'Admin':
        flash('Acceso denegado. Se requieren permisos de administrador.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        nuevo_estado = request.form.get('estado')
        
        estados_validos = ['Pendiente', 'En Proceso', 'Cerrado']
        if nuevo_estado not in estados_validos:
            flash('Estado no válido', 'danger')
            return redirect(url_for('admin_ver_patrullas'))
        
        reporte = PatrullaReporte.query.get_or_404(reporte_id)
        reporte.estado = nuevo_estado
        
        if nuevo_estado == 'Cerrado' and reporte.fecha_reparacion is None:
            reporte.fecha_reparacion = datetime.datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Estado del reporte #{reporte_id} actualizado a "{nuevo_estado}"', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error al actualizar el estado: {str(e)}', 'danger')
        current_app.logger.error(f"Error al cambiar estado de reporte patrulla: {e}")
    
    return redirect(url_for('admin_ver_patrullas'))


# ---------------------- ELIMINAR REPORTE DE PATRULLA ----------------------

@app.route('/admin/reportes/patrulla/<int:reporte_id>/eliminar', methods=['POST'])
@login_required
def eliminar_reporte_patrulla(reporte_id):
    if current_user.role != 'Admin':
        flash('Acceso denegado. Se requieren permisos de administrador.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        reporte = PatrullaReporte.query.get_or_404(reporte_id)
        unidad = reporte.unidad_numero
        
        db.session.delete(reporte)
        db.session.commit()
        
        flash(f'Reporte de la unidad {unidad} (ID #{reporte_id}) eliminado correctamente', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar el reporte: {str(e)}', 'danger')
        current_app.logger.error(f"Error al eliminar reporte de patrulla: {e}")
    
    return redirect(url_for('admin_ver_patrullas'))


# ---------------------- CAMBIAR ESTADO DE REPORTE DE EQUIPO ----------------------

@app.route('/admin/reportes/equipo/<int:reporte_id>/estado', methods=['POST'])
@login_required
def cambiar_estado_reporte_equipo(reporte_id):
    if current_user.role != 'Admin':
        flash('Acceso denegado. Se requieren permisos de administrador.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        nuevo_estado = request.form.get('estado')
        
        estados_validos = ['Pendiente', 'En Progreso', 'Reparado', 'Cerrado']
        if nuevo_estado not in estados_validos:
            flash('Estado no válido', 'danger')
            return redirect(url_for('admin_ver_equipos'))
        
        reporte = EquipoReporte.query.get_or_404(reporte_id)
        reporte.estado = nuevo_estado
        
        if nuevo_estado in ['Reparado', 'Cerrado'] and reporte.fecha_reparacion is None:
            reporte.fecha_reparacion = datetime.datetime.utcnow()
        elif nuevo_estado in ['Pendiente', 'En Progreso']:
            reporte.fecha_reparacion = None
        
        db.session.commit()
        
        flash(f'Estado del reporte #{reporte_id} actualizado a "{nuevo_estado}"', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error al actualizar el estado: {str(e)}', 'danger')
        current_app.logger.error(f"Error al cambiar estado de reporte equipo: {e}")
    
    return redirect(url_for('admin_ver_equipos'))


# ---------------------- ELIMINAR REPORTE DE EQUIPO ----------------------

@app.route('/admin/eliminar/equipo/<int:reporte_id>', methods=['POST'])
@login_required
def admin_eliminar_reporte_equipo(reporte_id):
    if current_user.role != 'Admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))

    reporte = EquipoReporte.query.get_or_404(reporte_id)

    try:
        db.session.delete(reporte)
        db.session.commit()
        flash(f"Reporte de Equipo ID {reporte_id} eliminado permanentemente.", "success")
        
    except Exception as e:
        db.session.rollback()
        flash("Error al intentar eliminar el reporte.", "danger")
        current_app.logger.error(f"Error al eliminar reporte de equipo: {e}")
        
    return redirect(url_for('admin_ver_equipos'))


# ---------------------- VER EQUIPOS ADMIN ----------------------
@app.route('/admin/ver_equipos')
@login_required
def admin_ver_equipos():
    if current_user.role != 'Admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))

    # ✅ CORRECCIÓN: Hacer JOIN con User para que coincida con el template
    reportes = db.session.query(EquipoReporte, User)\
        .join(User, EquipoReporte.user_id == User.id)\
        .order_by(EquipoReporte.fecha_reporte.desc())\
        .all()

    return render_template('admin_reportes_equipos.html', 
                            user=current_user, 
                            reportes=reportes)  # ← Debe ser 'reportes', no 'equipos'

# ---------------------- VER PATRULLAS ADMIN ----------------------


@app.route('/admin/ver_patrullas')
@login_required
def admin_ver_patrullas():
    if current_user.role != 'Admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('dashboard'))

    reportes_patrulla = (
        db.session.query(PatrullaReporte, User)
        .join(User)
        .order_by(PatrullaReporte.fecha_reporte.desc())
        .all()
    )

    return render_template(
        'admin_reportes_patrullas.html',
        user=current_user,
        reportes_patrulla=reportes_patrulla
    )

# ---------------------- ADMIN INICIAL ----------------------

def crear_admin_inicial():
    with app.app_context():
        db.create_all() 
        admin = User.query.filter_by(username='admin').first()

        if admin is None:
            admin = User(username='admin', role='Admin', sector='Administracion Central')
            admin.set_password('adminpass')
            db.session.add(admin)
            
            tecnico = User.query.filter_by(username='tecnico').first()
            if tecnico is None:
                tecnico = User(username='tecnico', role='Tecnico', sector='Global')
                tecnico.set_password('tecnicopass')
                db.session.add(tecnico)
                print("TECNICO CREADO -> usuario: tecnico  pass: tecnicopass (Sector: Global)")
                    
            tecnico_sector = User.query.filter_by(username='tecnico1').first()
            if tecnico_sector is None:
                tecnico_sector = User(username='tecnico1', role='Tecnico', sector='1')
                tecnico_sector.set_password('tecnicopass')
                db.session.add(tecnico_sector)
                print("TECNICO SECTORIZADO CREADO -> usuario: tecnico1  pass: tecnicopass (Sector: 1)")
                    
            oficial = User.query.filter_by(username='oficial').first()
            if oficial is None:
                oficial = User(username='oficial', role='Usuario', sector='1')
                oficial.set_password('oficialpass')
                db.session.add(oficial)
                print("OFICIAL CREADO -> usuario: oficial  pass: oficialpass (Sector: 1)")

            db.session.commit()
            print("ADMIN CREADO -> usuario: admin  pass: adminpass")


# ---------------------- RUN ----------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        crear_admin_inicial()

    app.run(debug=True)