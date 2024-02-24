import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MongobdDataSource} from '../datasources';
import {Rol, RolRelations} from '../models';

export class RolRepository extends DefaultCrudRepository<
  Rol,
  typeof Rol.prototype._id,
  RolRelations
> {
  constructor(
    @inject('datasources.mongobd') dataSource: MongobdDataSource,
  ) {
    super(Rol, dataSource);
  }
}
