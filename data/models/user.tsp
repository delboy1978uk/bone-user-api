import "../../../../../spec/models/common.tsp";

model User extends HasId {
  @example("bugs.bunny@looneytunes.com")
  email: string;

  person: Person;

  @example(1)
  state: int8;

  @example(plainDate.fromISO("2025-10-24 13:09:00"))
  registrationDate: plainDate;

  @example(plainDate.fromISO("2025-10-24 13:10:20"))
  lastLoginDate?: plainDate;

  @example("$2y$14$dVlHt/qKOYLPp/0/Gmu5XuPLg3oNsNHdYUPgRsc0NYpBvFSNB8gra")
  password: string;
}
