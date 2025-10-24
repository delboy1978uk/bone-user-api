import "@typespec/http";
import "@typespec/rest";
import "@typespec/openapi3";

using TypeSpec.Http;
using TypeSpec.Rest;

namespace Application;

@tag("Users")
@route("/users")
interface UserOps {
  @get
  op index(@query page?: int32): IndexResponse<User>;

  @post
  op create(@body UserBody: User): CreatedResponse<User>;

  @route("{id}")

  @get
  op get(@path id: int32): RecordResponse<User>;

  @patch(#{implicitOptionality: false})
  op update(@path id: int32, @body UserBody: User): UpdatedResponse<User>;

  @delete
  op delete(@path id: int32): DeletedResponse;
}
