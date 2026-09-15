import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

class Controller {
    @PreAuthorize("hasAuthority('NETWORK_TEST')")
    @PostMapping("/host-connectivity")
    public String testHostConnectivity(@RequestParam("address") String address) {
        return nacTestToolService.testHostConnectivity(address);
    }
}
