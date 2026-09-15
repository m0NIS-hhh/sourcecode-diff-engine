import org.springframework.web.bind.annotation.GetMapping;

class XmlController {
    @GetMapping("/xml")
    public String xml() {
        return "disabled";
    }
}
