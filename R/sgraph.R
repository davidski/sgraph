#' Retrieve OpenDNS Security Graph data
#'
#' This function will reach out to \url{https://www.opendns.org}, and retrieve
#' Security Graph for a passed IP or domain name.
#'
#' Your API key for OpenDNS's SecurityGraph must be specified in the system 
#' envrionment variable SGRAPH_API_KEY or passed via the auth_token parameter.
#'
#' @param url URL of the location for the tld name authority
#' @import httr
#' @export get_sgraph
#' @examples
#' \dontrun{
#' sgraph_data <- get_sgraph(domain = "www.google.com", auth_token="YOUR AUTH TOKEN HERE")
#' sgraph_data <- get_sgraph(ip = "8.8.8.8", auth_token="YOUR AUTH TOKEN HERE")
#' }
get_sgraph <- function(ip = NA, domain = NA, auth_token = NA) {
  if (is.na(auth_token)) {
    auth_token <- Sys.getenv("SGRAPH_API_KEY")
  }
  if (!is.na(ip)) {
    #returns history of the A records associated with this IP for the past 90 days
    ip_data <- GET(paste0("https://investigate.api.opendns.com/dnsdb/ip/a/", ip, ".json"), add_headers("Authorization"= paste("Bearer", auth_token)))
    
    #returns any currently known malware domains on this IP
    domains <- GET(paste0("https://investigate.api.opendns.com/ips/", ip, "/latest_domains"), add_headers("Authorization"= paste("Bearer", auth_token)))
    sgraph <- list(ip_data=content(ip_data), malware_domains=content(domains))
  } else {
    #returns status   integer 	The status will be "-1" if the domain is believed to be malicious, "1" if the domain is believed to be benign, "0" if it hasn't been classified yet
    #security_categories 	array of strings 	The OpenDNS security category or categories that match this domain. If none match, the return will be blank.
    #content_categories 	array of strings 	The OpenDNS content category or categories that match this domain. If none match, the return will be blank.
    domain_category <- GET(paste0("https://investigate.api.opendns.com/domains/categorization/", domain), add_headers("Authorization"= paste("Bearer", auth_token)))
    
    
    domain_name <- GET(paste0("https://investigate.api.opendns.com/security/name/", domain), add_headers("Authorization"= paste("Bearer", auth_token)))
    domain_name <- content(domain_name)
    domain_name <- unlist(strsplit(domain_name, "\n"))
    sgraph <- list(category=content(domain_category), name=domain_name)
  }
  sgraph
}