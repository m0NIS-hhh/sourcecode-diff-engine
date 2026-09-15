import java.net.URL;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class Controller {
    @GetMapping("/fetch")
    public String fetch(@RequestParam("url") String url) throws Exception {
        URL target = new URL(url);
        return target.openConnection().getContentType();
    }
}
