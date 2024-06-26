import {inject, lifeCycleObserver, LifeCycleObserver} from '@loopback/core';
import {juggler} from '@loopback/repository';
import {ConfiguracionSeguridad} from '../config/seguridad.config';

const config = {
  name: 'mongobd',
  connector: 'mongodb',
  url: ConfiguracionSeguridad.mongodbConnetionString,
  host: 'localhost',
  port: 27017,
  user: '',
  password: '',
  database: 'seguridad_ventas',
  useNewUrlParser: true
};

// Observe application's life cycle to disconnect the datasource when
// application is stopped. This allows the application to be shut down
// gracefully. The `stop()` method is inherited from `juggler.DataSource`.
// Learn more at https://loopback.io/doc/en/lb4/Life-cycle.html
@lifeCycleObserver('datasource')
export class MongobdDataSource extends juggler.DataSource
  implements LifeCycleObserver {
  static dataSourceName = 'mongobd';
  static readonly defaultConfig = config;

  constructor(
    @inject('datasources.config.mongobd', {optional: true})
    dsConfig: object = config,
  ) {
    super(dsConfig);
  }
}
