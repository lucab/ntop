

ntop.send_http_header(1, 'Known ntop hosts(' .. ntop.getQueryString() .. ')')
ntop.sendString("Hello world, from ".. _VERSION .. "<p>")
ntop.getFirstHost(0);

-- Example: how to set IP address
-- host.ipAddress("1.2.3.4")

ntop.sendString("<ol>\n");
while ntop.getNextHost(0) do
   if(host.ipAddress() == "") then
       ntop.sendString("<li> <A HREF=\"/" .. host.ethAddress() .. ".html\">" .. string.gsub(host.ethAddress(), ':', '_'))
   else
       ntop.sendString("<li> <A HREF=\"/" .. host.ipAddress() .. ".html\">" .. host.ipAddress());
   end

   ntop.sendString("</A> [sent=".. host.pktSent() .. " / rcvd=" .. host.pktRcvd().. "]</li>\n")
end
ntop.sendString("</ol>\n");

ntop.send_html_footer()