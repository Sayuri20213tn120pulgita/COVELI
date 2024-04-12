from flask import Flask, render_template, request, url_for, redirect, flash, jsonify
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail

from werkzeug.security import check_password_hash, generate_password_hash

from .models.ModeloCompra import ModeloCompra
from .models.ModeloLibro import ModeloLibro
from .models.ModeloUsuario import ModeloUsuario

from .models.entities.Usuario import Usuario
from .models.entities.Compra import Compra
from .models.entities.Libro import Libro


from .consts import *
from .emails import confirmacion_compra, confirmacion_registro_usuario

app = Flask(__name__)

csrf = CSRFProtect()
db = MySQL(app)
login_manager_app = LoginManager(app)
mail = Mail()


@login_manager_app.user_loader
def load_user(id):
    return ModeloUsuario.obtener_por_id(db, id)



# @app.route("/password/<password>")
# def generar_password(password):
#     encriptado = generate_password_hash(password)
#     valor = check_password_hash(encriptado, password)
#     return "Encriptado: {0} ! Coincide: {1}".format(encriptado, valor)

@app.route("/login", methods = ['GET','POST'])
def login():
    # print(f"El metodo es: {request.method}")
    # print(f"EL usuario es: {request.form['usuario']}")
    # print(f"La contraseña es: {request.form['password']}")

    if request.method == 'POST':
        usuario = Usuario(None, request.form['usuario'], request.form['password'], None, None, None, None, None, None, None)
        usuario_logueado = ModeloUsuario.login(db,usuario)
        if usuario_logueado != None:
            login_user(usuario_logueado)
            flash(MENSAJE_BIENVENIDA, 'success')
            return redirect(url_for('index'))
        else:
            flash(LOGIN_CREDENCIALESINVALIDAS, 'warning')
            return render_template('auth/login.html')
    else:
        return render_template('auth/login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash(LOGOUT, 'success')
    return redirect(url_for('login'))

@app.route('/registrar', methods = ['GET','POST'])
def registrar():
    """Funcion para que el usuario se registre"""

    if request.method == 'POST':
        usuario = request.form.get('usuario')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        tipousuario_id = request.form.get('tipousuario_id')
        nombre = request.form.get('nombre')
        apellido_p = request.form.get('apellidoPaterno')
        apellido_m = request.form.get('apellidoMaterno')
        direccion = request.form.get('direccion')
        correo = request.form.get('correo')
        telefono = request.form.get('telefono')

        usuario_existe = ModeloUsuario.usuario_existe(db,usuario)
        correo_existe = ModeloUsuario.correo_existe(db,correo)

        if len(usuario) < 6:
            flash('El usuario debe tener al menos seis caracteres', 'warning')
        elif len(password) < 6:
            flash('La contraseña debe tener al menos seis caracteres', 'warning')
        elif usuario_existe == True:
            flash('El usuario ya existe en la base de datos, ingresa otro nombre', 'warning')
        elif correo_existe == True:
            flash('El correo ya existe en la base de datos, ingresa otro correo', 'warning')
        else:
            # Crear instancia de la clase usuario y se mandan los parametros
            user = Usuario(None, usuario, hashed_password, tipousuario_id, nombre, apellido_p, apellido_m, direccion, correo, telefono)

            usuario_creado = ModeloUsuario.registar_usuario(db, user)

            if usuario_creado == True:
                print('Se creo el usuario correctamente')
                flash(USUARIO_CREADO, 'success')
                confirmacion_registro_usuario(app, mail, correo)
                return redirect(url_for('registrar'))
            else:
                flash(USUARIO_ERROR, 'success')
                print('El usuario no se creo correctamente, checa las sentencias')

    return render_template('registar.html')


@app.route("/")
@login_required
def index():
    if current_user.is_authenticated:
        if current_user.tipousuario.id == 1:
            try:
                libros_vendidos = ModeloLibro.listar_libros_vendidos(db)
                # libros_vendidos = []
                data = {
                    'titulo' : 'Libros vendidos',
                    'libros_vendidos' : libros_vendidos
                }
                return render_template('index.html', data = data)
            except Exception as ex:
                return render_template('errores/error.html', mensaje = format(ex))
        else:
            try:
                compras = ModeloCompra.listar_compras_usuario(db, current_user)
                data = {
                    'titulo' : 'Mis compras',
                    'compras' : compras
                }
                return render_template('index.html', data = data)
            except Exception as ex:
                return render_template('errores/error.html', mensaje = format(ex))
    else:
        return redirect(url_for('login'))

@app.route("/libros")
@login_required
def listar_libros():
    try:
        libros = ModeloLibro.listar_libros(db)
        data = {
            'titulo' : 'Libros',
            'libros' : libros
        }
        return render_template('listado_libros.html', data = data)
    except Exception as ex:
        return render_template('errores/error.html', mensaje = format(ex))

@app.route("/comprarLibro", methods=['POST'])
@login_required
def comprar_libro():
    data_request = request.get_json()
    print(f"El isbn es: {data_request}")
    data = {}
    try:
        # libro = Libro(data_request['isbn'], None, None, None, None)
        libro = ModeloLibro.leer_libro(db, data_request['isbn'])
        compra = Compra(None, libro, current_user)
        data['exito'] = ModeloCompra.registrar_compra(db, compra)

        # confirmacion_compra(mail, current_user, libro) Envio normal
        confirmacion_compra(app, mail, current_user, libro) # Envio asincrono
    except Exception as ex:
        data['mensaje'] = format(ex)
        data['exito'] = False
    return jsonify(data)


def pagina_no_encontrada(error):
    return render_template('errores/404.html'), 404

def pagina_no_autorizada(error):
    return redirect(url_for('login'))
    
def inicializar_app(config):
    app.config.from_object(config)
    csrf.init_app(app)
    mail.init_app(app)
    app.register_error_handler(401, pagina_no_autorizada)
    app.register_error_handler(404, pagina_no_encontrada)
    return app