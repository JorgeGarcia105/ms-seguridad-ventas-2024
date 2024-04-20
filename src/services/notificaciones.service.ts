import {BindingScope, injectable} from '@loopback/core';
const fetch = require('node-fetch');

@injectable({scope: BindingScope.TRANSIENT})
export class NotificacionesService {
  constructor(/* Add @inject to inject parameters */) { }

  /*
   * Add service methods here
   */

  EnviarNotificacion(datos: any, url: string) {
    fetch(url, {
      method: 'post',
      datos: JSON.stringify(datos),
      headers: {'Content-Type': 'application/json'},
    })
  }
}

