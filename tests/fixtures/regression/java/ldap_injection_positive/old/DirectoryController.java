import org.springframework.web.bind.annotation.GetMapping;

class DirectoryController {
    @GetMapping("/lookup")
    public String lookup() {
        return "disabled";
    }
}
