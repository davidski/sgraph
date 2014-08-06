#' Retrieve OpenDNS Security Graph data
#'
#' This function will reach out to \url{https://www.opendns.org}, and retrieve
#' Security Graph for a passed IP or domain name.
#'
#'
#' @param url URL of the location for the tld name authority
#' @import httr
#' @export get_sgraph
#' @examples
#' \dontrun{
#' sgraph_data <- get_sgraph(domain = "www.google.com", auth_token="YOUR AUTH TOKEN HERE")
#' }
get_sgraph <- function(ip = NA, domain = NA, auth_token = NA) {
  if (!is.na(ip)) {
    ip_data <- GET(paste0("https://investigate.api.opendns.com/dnsdb/ip/a/", ip, ".json"), add_headers("Authorization"= paste("Bearer", auth_token)))
    domains <- GET(paste0("https://investigate.api.opendns.com/ips/", ip, "/latest_domains"), add_headers("Authorization"= paste("Bearer", auth_token)))
    sgraph <- list(ip_data=content(ip_data), domain_data=content(domains))
  } else {
    domain_category <- GET(paste0("https://investigate.api.opendns.com/domains/categorization/", domain), add_headers("Authorization"= paste("Bearer", auth_token)))
    domain_name <- GET(paste0("https://investigate.api.opendns.com/security/name/", domain), add_headers("Authorization"= paste("Bearer", auth_token)))
    domain_name <- content(domain_name)
    domain_name <- unlist(strsplit(domain_name, "\n"))
    sgraph <- list(category=content(domain_category), name=domain_name)
  }
  sgraph
}