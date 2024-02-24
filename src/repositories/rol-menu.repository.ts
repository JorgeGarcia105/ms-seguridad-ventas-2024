import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MongobdDataSource} from '../datasources';
import {RolMenu, RolMenuRelations} from '../models';

export class RolMenuRepository extends DefaultCrudRepository<
  RolMenu,
  typeof RolMenu.prototype._id,
  RolMenuRelations
> {
  constructor(
    @inject('datasources.mongobd') dataSource: MongobdDataSource,
  ) {
    super(RolMenu, dataSource);
  }
}
