import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class DirectoryController {
    private DirContext ctx;

    @GetMapping("/lookup")
    public Object lookup(@RequestParam("uid") String uid) throws Exception {
        String filter = "(uid=" + uid + ")";
        return ctx.search("ou=people", filter, new SearchControls());
    }
}
