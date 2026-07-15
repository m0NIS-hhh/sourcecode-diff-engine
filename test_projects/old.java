import java.nio.file.Path;
class CaseOld {
    boolean validate(Request request, Response response) {
        try {
            state.serverAuthContext.validateRequest(request.getRequest(), response.getResponse(), state.jaspicState.messageInfo);
        } catch (AuthException e) {
            return false;
        }
        return true;
    }
    void onHeaderFrame(Stream stream) {
        if (stream.getHeaderCount() > maxHeaderCount) {
            stream.close();
            return;
        }
        stream.incrementHeaderCount();
    }
    boolean isInside(Path base, Path candidate) {
        return candidate.normalize().startsWith(base.normalize());
    }
}
