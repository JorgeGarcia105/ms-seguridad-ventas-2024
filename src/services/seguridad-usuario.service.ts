import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {ConfiguracionSeguridad} from '../config/seguridad.config';
import {Credenciales, FactorDeAutentificacionPorCodigo, RolMenu, Usuario} from '../models';
import {LoginRepository, RolMenuRepository, UsuarioRepository} from '../repositories';
const generator = require('generate-password');
const MD5 = require("crypto-js/md5");
const jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository,
    @repository(RolMenuRepository)
    private repositorioRolMenu: RolMenuRepository
  ) { }

  /**
   * Crear un clave aleatoria
   * @returns cadena aleatoria de n caracteres
   */
  crearTextoAleatorio(n: number): string {
    const clave = generator.generate({
      length: n,
      numbers: true
    });
    return clave;
  }

  /**
   * Cifrar una cadena de con metodo MD5
   * @param cadena texto a cifrar
   * @returns cadena cifrada con MD5
   */
  cifrarTexto(cadena: string): string {
    const cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }

  /**
   * Se busca un usuario por sus credenciales de acceso
   * @param credenciales del usuario
   * @returns usuario encontrado o null
   */
  async identificarUsuario(credenciales: Credenciales): Promise<Usuario | null> {
    const usuario = await this.repositorioUsuario.findOne({
      where: {
        correo: credenciales.correo,
        clave: credenciales.clave,
        estadoValidacion: true,
        aceptado: true
      }
    });
    return usuario as Usuario;
  }

  /**
   * Valida un codigo 2fa para un usuario
   * @param credencialesafa credenciales del usuario con el codigo 2fa
   * @returns el registro de login o null
   */
  async validarCodigo2fa(credenciales2fa: FactorDeAutentificacionPorCodigo): Promise<Usuario | null> {
    const login = await this.repositorioLogin.findOne({
      where: {
        usuarioId: credenciales2fa.usuarioId,
        codigo2fa: credenciales2fa.codigo2fa,
        estadoCodigo2fa: false
      }
    });
    if (login) {
      const usuario = this.repositorioUsuario.findById(credenciales2fa.usuarioId);
      return usuario;
    }
    return null;
  }

  /**
   * Geracion del JWT para el usuario
   * @param usuario informacion del usuario
   * @returns token
   */
  crearToken(usuario: Usuario): string {
    const datos = {
      name: `${usuario.primerNombre} ${usuario.segundoNombre} ${usuario.primerApellido} ${usuario.segundoApellido}`,
      role: usuario.rolId,
      email: usuario.correo
    };
    const token = jwt.sign(datos, ConfiguracionSeguridad.claveJWT)
    return token;
  }

  /**
   * Validar y Obtener el rol del token
   * @param tk token
   * @returns id del rol del usuario
   */
  obtenerRolDesdeToken(tk: string): string {
    const obj = jwt.verify(tk, ConfiguracionSeguridad.claveJWT)
    return obj.role
  }

  /**
   * Retorna los permisos del rol
   * @param idRol id del rol a buscar y que esta asociado al usuario
   */
  async consultarLosPermisosDeMenuPorUsuario(idRol: string): Promise<RolMenu[]> {
    let menu: RolMenu[] = await this.repositorioRolMenu.find({
      where: {
        listar: true,
        rolId: idRol
      }
    })
    return menu;
  }
}
