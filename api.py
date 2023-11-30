# UNIVERSIDAD DE LAS FUERZAS ARMADAS ESPE
# RICARDO SEBASTIAN GRIJALVA MOREJON
#Desarrollo de un microservicio aplicando los principios CID
from flask import Flask, request, jsonify
import mysql.connector
from passlib.hash import argon2
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, Regexp
import jwt 
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mi_secreto_super_seguro'
# Configuración de la base de datos
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'seguro'
}

# Conexión a la base de datos
conn = mysql.connector.connect(**db_config)
cursor = conn.cursor()

@app.route('/usuarios', methods=['GET'])
def obtener_usuarios():
    try:
        # Obtener todos los usuarios de la base de datos
        cursor.execute("SELECT codigo, usuario, correo, contrasenia FROM usuarios")
        usuarios = cursor.fetchall()

        # Convertir el resultado a un formato JSON
        usuarios_json = []
        for usuario in usuarios:
            usuario_dict = {
                'codigo': usuario[0],
                'usuario': usuario[1],
                'correo': usuario[2],
                'contrasenia': usuario[3]
            }
            usuarios_json.append(usuario_dict)

        return jsonify({'usuarios': usuarios_json}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/usuarios/<codigo>', methods=['DELETE'])
def eliminar_usuario(codigo):
    try:
        # Eliminar usuario de la base de datos
        cursor.execute("DELETE FROM usuarios WHERE codigo=%s", (codigo,))
        conn.commit()

        return jsonify({'mensaje': 'Usuario eliminado correctamente'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

class CrearUsuarioForm(FlaskForm):
    codigo = StringField('Codigo', validators=[InputRequired()])
    usuario = StringField('Usuario', validators=[InputRequired()])
    contrasenia = PasswordField('Contraseña', validators=[
        InputRequired(),
        Length(min=8, message='La contraseña debe tener al menos 8 caracteres.'),
        Regexp(
            regex=r'^(?=.*[a-zA-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
            message='La contraseña debe contener al menos una letra, un número y un símbolo.'
        )
    ])
    correo = StringField('Correo', validators=[InputRequired()])
app.config['WTF_CSRF_ENABLED'] = False
@app.route('/usuarios', methods=['POST'])
def crear_usuario():
    try:
        data = request.get_json()  # Cambia esta línea para obtener datos JSON
        form = CrearUsuarioForm(data=data)  # Pasa los datos JSON al formulario
        print(data)
        print(form.data)
        if form.validate():
            # El formulario es válido, procede con la creación del usuario
            codigo = form.codigo.data
            usuario = form.usuario.data
            contrasenia = form.contrasenia.data
            correo = form.correo.data

            # Cifrar la contraseña antes de almacenarla
            contrasenia_cifrada = argon2.hash(contrasenia)

            # Insertar usuario en la base de datos con la contraseña cifrada
            cursor.execute("INSERT INTO usuarios (codigo, usuario, contrasenia, correo) VALUES (%s, %s, %s, %s)",
                           (codigo, usuario, contrasenia_cifrada, correo))
            conn.commit()

            return jsonify({'mensaje': 'Usuario creado correctamente'}), 201
        else:
            # El formulario no es válido, retorna errores de validación
            return jsonify({'error': form.errors}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/usuarios/<codigo>', methods=['PUT'])
def actualizar_usuario(codigo):
    try:
        data = request.get_json()
        usuario = data['usuario']
        contrasenia = data['contrasenia']
        correo = data['correo']

        # Cifrar la nueva contraseña antes de almacenarla
        contrasenia_cifrada = argon2.hash(contrasenia)

        # Actualizar usuario en la base de datos con la nueva contraseña cifrada
        cursor.execute("UPDATE usuarios SET usuario=%s, contrasenia=%s, correo=%s WHERE codigo=%s",
                       (usuario, contrasenia_cifrada, correo, codigo))
        conn.commit()

        return jsonify({'mensaje': 'Usuario actualizado correctamente'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/usuarios/verificar', methods=['POST'])
def verificar_usuario():
    try:
        data = request.get_json()
        codigo = data['codigo']
        contrasenia_ingresada = data['contrasenia']

        # Obtener la información del usuario desde la base de datos
        cursor.execute("SELECT contrasenia FROM usuarios WHERE codigo=%s", (codigo,))
        usuario_info = cursor.fetchone()

        if usuario_info:
            # Verificar si la contraseña ingresada es correcta
            contrasenia_cifrada_almacenada = usuario_info[0]
            if argon2.verify(contrasenia_ingresada, contrasenia_cifrada_almacenada):
                return jsonify({'mensaje': 'Contraseña correcta'}), 200
            else:
                return jsonify({'mensaje': 'Contraseña incorrecta'}), 401
        else:
            return jsonify({'mensaje': 'Usuario no encontrado'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    # Secreto para firmar y verificar tokens JWT
SECRET_KEY = "mi_secreto_super_seguro"

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        codigo = data['codigo']
        contrasenia_ingresada = data['contrasenia']

        # Obtener la información del usuario desde la base de datos
        cursor.execute("SELECT codigo, contrasenia FROM usuarios WHERE codigo=%s", (codigo,))
        usuario_info = cursor.fetchone()

        if usuario_info:
            # Verificar si la contraseña ingresada es correcta
            contrasenia_cifrada_almacenada = usuario_info[1]
            if argon2.verify(contrasenia_ingresada, contrasenia_cifrada_almacenada):
                # Generar token JWT
                token = jwt.encode({'codigo': codigo}, SECRET_KEY, algorithm='HS256')
                return jsonify({'token': token}), 200
            else:
                return jsonify({'mensaje': 'Contraseña incorrecta'}), 401
        else:
            return jsonify({'mensaje': 'Usuario no encontrado'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
