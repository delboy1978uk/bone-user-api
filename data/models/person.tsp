import "../../../../../spec/models/common.tsp";

model Person extends HasId {
  @example("George")
  firstname: string;

  @example("Washington")
  middlename: string;

  @example("Bunny")
  lastname: string;

  @example("Bugs")
  aka: string;

  @example(plainDate.fromISO("1938-04-30"))
  dob: plainDate;

  @example("Brooklyn, New York")
  birthplace: string;

  @example("US")
  country: string;

  @example("img/rabbit.png")
  image: string;

  @example("img/background.jpg")
  backgroundImage: string;
}
