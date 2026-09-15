import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.w3c.dom.Document;

class XmlController {
    private Document document;

    @GetMapping("/xml")
    public String xml(@RequestParam("name") String name) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        return xpath.evaluate("//user[name='" + name + "']/role", document);
    }
}
