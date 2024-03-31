export namespace ConfiguracionNotificaciones {
  export const asunto2fa: string = "Código de verificación";
  export const asuntoVerificacionCorreo: string = "Validación de correo";
  export const claveAsignada: string = "Clave asignada";
  export const urlNotificacio2fa: string = "http://localhost:5093/Notificaciones/enviar-correo-2fa";
  export const urlNotificacioSms: string = "http://localhost:5093/Notificaciones/enviar-sms";
  export const urlValidacionCorreoFrontend: string = "http://localhost:4200/seguridad/validar-hash-usuario-publico";
}
