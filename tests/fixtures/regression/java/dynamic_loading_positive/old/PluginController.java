import org.springframework.web.bind.annotation.GetMapping;

class PluginController {
    @GetMapping("/plugin")
    public String plugin() {
        return "disabled";
    }
}
