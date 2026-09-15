import java.nio.file.Files;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

class UploadController {
    @PostMapping("/upload")
    public void upload(@RequestParam("file") MultipartFile file) throws Exception {
        String name = file.getOriginalFilename();
        Files.write(Paths.get(name), file.getBytes());
    }
}
