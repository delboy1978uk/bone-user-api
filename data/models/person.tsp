import "../../../../../spec/models/common.tsp";

model Person extends HasId {
  firstname: string;
  middlename: string;
  lastname: string;
  aka: string;
  birthplace: string;
  counttry: string;
}
