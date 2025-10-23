import "@typespec/http";
import "@typespec/rest";
import "@typespec/openapi3";

using TypeSpec.Http;
using TypeSpec.Rest;

namespace Application;

@tag("People")
@route("/people")
interface PeopleOps {
  @get
  op index(@query page?: int32): IndexResponse<Person>;

  @post
  op create(@body PersonBody: Person): CreatedResponse<Person>;

  @route("{id}")

  @get
  op get(@path id: int32): RecordResponse<Person>;

  @patch(#{implicitOptionality: false})
  op update(@path id: int32, @body PersonBody: Person): UpdatedResponse<Person>;

  @delete
  op delete(@path id: int32): DeletedResponse;
}
