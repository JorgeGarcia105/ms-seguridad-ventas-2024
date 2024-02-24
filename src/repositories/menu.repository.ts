import {Getter, inject} from '@loopback/core';
import {DefaultCrudRepository, HasManyThroughRepositoryFactory, repository} from '@loopback/repository';
import {MongobdDataSource} from '../datasources';
import {Menu, MenuRelations, Rol, RolMenu} from '../models';
import {RolMenuRepository} from './rol-menu.repository';
import {RolRepository} from './rol.repository';

export class MenuRepository extends DefaultCrudRepository<
  Menu,
  typeof Menu.prototype._id,
  MenuRelations
> {

  public readonly roles: HasManyThroughRepositoryFactory<Rol, typeof Rol.prototype._id,
    RolMenu,
    typeof Menu.prototype._id
  >;

  constructor(
    @inject('datasources.mongobd') dataSource: MongobdDataSource, @repository.getter('RolMenuRepository') protected rolMenuRepositoryGetter: Getter<RolMenuRepository>, @repository.getter('RolRepository') protected rolRepositoryGetter: Getter<RolRepository>,
  ) {
    super(Menu, dataSource);
    this.roles = this.createHasManyThroughRepositoryFactoryFor('roles', rolRepositoryGetter, rolMenuRepositoryGetter,);
    this.registerInclusionResolver('roles', this.roles.inclusionResolver);
  }
}
