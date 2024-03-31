export namespace ConfiguracionSeguridad {
  export const claveJWT = process.env.SECRET_PASSWORD_JWT;
  export const menuUsuarioId = "65d93f7450ccdd55b038cd66";
  export const listarAccion = "listar";
  export const guardarAccion = "guardar";
  export const editarAccion = "editar";
  export const eliminarAccion = "eliminar";
  export const descargarAccion = "descargar";
  export const mongodbConnetionString = process.env.CONNECTION_STRING_MONGODB;
  export const rolUsuarioPublico = "6608a58d4730d15e04baa0fe";
}
