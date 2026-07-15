import java.nio.file.Path;
class CaseNew {
    boolean validate(Request request, Response response) {
        try {
            state.serverAuthContext.validateRequest(request.getRequest(), response.getResponse(), state.jaspicState.messageInfo);
        } catch (AuthException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return false;
        }
        return true;
    }
    void onHeaderFrame(Stream stream) {
        if (stream.getHeaderCount() >= maxHeaderCount) {
            stream.decrementActiveCount();
            stream.close();
            return;
        }
        stream.incrementHeaderCount();
    }
    boolean isInside(Path base, Path candidate) {
        Path b = base.toAbsolutePath().normalize();
        Path c = candidate.toAbsolutePath().normalize();
        return c.startsWith(b) && c.getNameCount() >= b.getNameCount();
    }
}
