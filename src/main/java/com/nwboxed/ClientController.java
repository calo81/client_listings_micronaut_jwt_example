package com.nwboxed;

import io.micronaut.http.annotation.*;
import io.micronaut.http.MediaType;

import java.util.List;

@Controller("/client")
public class ClientController {

    @Get(uri="/{client_id}/shares", produces=MediaType.TEXT_HTML)
    public String getClientShares(@PathVariable String client_id) {
        List<String> shares = List.of("Share A", "Share B", "Share C");

        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>Shares for client: ").append(client_id).append("</h1>");
        html.append("<ul>");
        for (String share : shares) {
            html.append("<li>").append(share).append("</li>");
        }
        html.append("</ul>");
        html.append("</body></html>");

        return html.toString();
    }
}
