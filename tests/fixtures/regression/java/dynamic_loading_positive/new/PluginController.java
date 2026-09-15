import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class PluginController {
    @GetMapping("/plugin")
    public Object plugin(@RequestParam("className") String className) throws Exception {
        Class<?> pluginClass = Class.forName(className);
        return pluginClass.getDeclaredConstructor().newInstance();
    }
}
