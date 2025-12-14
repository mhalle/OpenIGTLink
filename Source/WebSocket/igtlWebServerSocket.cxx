//
//  igtlWebServerSocket.cpp
//  OpenIGTLink
//
//  Created by Longquan Chen on 1/20/17.
//
//

#include "igtlWebServerSocket.h"

webSocketServer::webSocketServer()
  : m_count(0)
  , m_originValidationMode(ORIGIN_ALLOW_ALL)
  , m_maxHttpFileSize(100 * 1024 * 1024)  /* Default: 100 MB */
{
  // set up access channels to only log interesting things
  m_endpoint.clear_access_channels(websocketpp::log::alevel::all);
  m_endpoint.set_access_channels(websocketpp::log::alevel::access_core);
  m_endpoint.set_access_channels(websocketpp::log::alevel::app);

  // Initialize the Asio transport policy
  m_endpoint.init_asio();

  // Bind the handlers we are using
  using websocketpp::lib::placeholders::_1;
  m_endpoint.set_open_handler(bind(&webSocketServer::on_open,this,_1));
  m_endpoint.set_close_handler(bind(&webSocketServer::on_close,this,_1));
  m_endpoint.set_http_handler(bind(&webSocketServer::on_http,this,_1));
  m_endpoint.set_validate_handler(bind(&webSocketServer::on_validate,this,_1));
  m_timeInterval = 1;
}

void webSocketServer::SetTimeInterval(unsigned int time)
{
  this->m_timeInterval = time;
}

int webSocketServer::CreateServer(uint16_t port)
{
  return this->run("",port);
}

int webSocketServer::CreateHTTPServer(std::string docroot, uint16_t port)
{
  m_docroot = docroot;
  this->port = port;
  return this->run(docroot,port);
}

webSocketServer* webSocketServer::WaitForConnection(unsigned long msec )
{
  if(m_connections.size())
    {
    return this;
    }
  else
    {
    igtl::Sleep(msec);
    return NULL;
    }
}

int webSocketServer::run(std::string docroot, uint16_t port) {
  m_docroot = docroot;
  serverCreated = false;
  //------------------------------------------------------------
  // Get thread information
  //igtl::MultiThreader::ThreadInfo* info =
  //static_cast<igtl::MultiThreader::ThreadInfo*>(ptr);
  std::stringstream ss;
  ss << "Running server on port "<< this->port <<" using docroot=" << this->m_docroot;
  this->m_endpoint.get_alog().write(websocketpp::log::alevel::app,ss.str());
  
  
  // listen on specified port
  this->m_endpoint.listen(this->port);
  
  // Start the server accept loop
  this->m_endpoint.start_accept();
  
  set_timer();
  // Start the ASIO io_service run loop
  try
  {
  this->m_endpoint.run();
  }
  catch (websocketpp::exception const & e)
  {
  std::cout << e.what() << std::endl;
  this->status = -1;
  }
  this->status = 0;
  return status;
}

void webSocketServer::Send(void * inputMessage, size_t len)
{
  {
  unique_lock<mutex> lock(m_action_lock);
  char * str = new char[len];
  memcpy(str, inputMessage, len);
  std::string msg(str, len);
  m_actions.push(action(MESSAGE,msg));
  delete [] str;
  }
  m_action_cond.notify_one();
  m_count++;
}

void webSocketServer::set_timer() {
  m_timer = m_endpoint.set_timer(this->m_timeInterval,
                                 websocketpp::lib::bind( &webSocketServer::on_timer, this)
                                 );
}

void webSocketServer::on_timer() {
  // Broadcast count to all connections
  unique_lock<mutex> lock(m_action_lock);
  
  while(m_actions.empty()) {
    m_action_cond.wait(lock);
  }
  action a = m_actions.front();
  m_actions.pop();
  lock.unlock();
  
  con_list::iterator it;
  for (it = m_connections.begin(); it != m_connections.end(); ++it) {
    if (a.msg.length())
      {
      m_endpoint.send(*it,a.msg,websocketpp::frame::opcode::binary);
      }
  }
  // set timer for next telemetry check
  set_timer();
}

void webSocketServer::on_http(connection_hdl hdl) {
  // Upgrade our connection handle to a full connection_ptr
  server::connection_ptr con = m_endpoint.get_con_from_hdl(hdl);

  std::ifstream file;
  std::string filename = con->get_resource();
  std::string response;

  // Security: Reject path traversal attempts
  if (filename.find("..") != std::string::npos)
    {
    con->set_body("<!doctype html><html><head><title>Error 403</title></head>"
                  "<body><h1>Error 403 - Forbidden</h1></body></html>");
    con->set_status(websocketpp::http::status_code::forbidden);
    return;
    }

  // Security: Reject paths with null bytes (truncation attacks)
  if (filename.find('\0') != std::string::npos)
    {
    con->set_body("<!doctype html><html><head><title>Error 400</title></head>"
                  "<body><h1>Error 400 - Bad Request</h1></body></html>");
    con->set_status(websocketpp::http::status_code::bad_request);
    return;
    }

  //m_endpoint.get_alog().write(websocketpp::log::alevel::app, "http request1: "+filename);

  if (filename == "/")
    {
    filename = m_docroot+"index.html";
    }
  else
    {
    filename = m_docroot+filename.substr(1);
    }

  //m_endpoint.get_alog().write(websocketpp::log::alevel::app, "http request2: "+filename);

  file.open(filename.c_str(), std::ios::in | std::ios::binary);
  if (!file)
    {
    // 404 error
    std::stringstream ss;

    ss << "<!doctype html><html><head>"
    << "<title>Error 404 (Resource not found)</title><body>"
    << "<h1>Error 404</h1>"
    << "<p>The requested URL " << filename << " was not found on this server.</p>"
    << "</body></head></html>";

    con->set_body(ss.str());
    con->set_status(websocketpp::http::status_code::not_found);
    return;
    }

  /* Security: Enforce maximum file size to prevent memory exhaustion attacks.
     Without a limit, an attacker can request large files and force the server
     to allocate unbounded memory, causing crashes or DoS.
     Default is 100MB, configurable via SetMaxHttpFileSize(). */
  file.seekg(0, std::ios::end);
  std::streampos fileSize = file.tellg();

  if (fileSize < 0 || static_cast<size_t>(fileSize) > m_maxHttpFileSize)
    {
    file.close();
    con->set_body("<!doctype html><html><head><title>Error 413</title></head>"
                  "<body><h1>Error 413 - Payload Too Large</h1>"
                  "<p>The requested file exceeds the maximum allowed size.</p></body></html>");
    con->set_status(websocketpp::http::status_code::request_entity_too_large);
    return;
    }

  file.seekg(0, std::ios::beg);

  /* Reserve and read with validated size */
  try
    {
    response.reserve(static_cast<size_t>(fileSize));
    response.assign((std::istreambuf_iterator<char>(file)),
                    std::istreambuf_iterator<char>());
    }
  catch (const std::bad_alloc&)
    {
    file.close();
    con->set_body("<!doctype html><html><head><title>Error 500</title></head>"
                  "<body><h1>Error 500 - Internal Server Error</h1></body></html>");
    con->set_status(websocketpp::http::status_code::internal_server_error);
    return;
    }

  file.close();
  con->set_body(response);
  con->set_status(websocketpp::http::status_code::ok);
}

void webSocketServer::on_open(connection_hdl hdl) {
  m_connections.insert(hdl);
}

void webSocketServer::on_close(connection_hdl hdl) {
  m_connections.erase(hdl);
}

bool webSocketServer::on_validate(connection_hdl hdl) {
  // Allow all connections if validation is disabled (default)
  if (m_originValidationMode == ORIGIN_ALLOW_ALL)
    {
    return true;
    }

  server::connection_ptr con = m_endpoint.get_con_from_hdl(hdl);
  std::string origin = con->get_request_header("Origin");

  if (m_originValidationMode == ORIGIN_LOCALHOST_ONLY)
    {
    // Check if origin is localhost (any port)
    // Valid patterns: http://localhost, http://localhost:PORT,
    //                 http://127.0.0.1, http://127.0.0.1:PORT,
    //                 https:// variants, and file://
    if (origin.empty())
      {
      // No origin header - could be non-browser client, allow it
      return true;
      }
    if (origin == "file://")
      {
      return true;
      }
    // Check for localhost patterns
    if (origin.find("://localhost") != std::string::npos ||
        origin.find("://127.0.0.1") != std::string::npos ||
        origin.find("://[::1]") != std::string::npos)
      {
      return true;
      }
    // Reject non-localhost origins
    return false;
    }

  if (m_originValidationMode == ORIGIN_CUSTOM)
    {
    // No origin header - could be non-browser client, allow it
    if (origin.empty())
      {
      return true;
      }
    // Check against allowed origins list
    if (m_allowedOrigins.find(origin) != m_allowedOrigins.end())
      {
      return true;
      }
    // Check for prefix match (to handle ports)
    for (std::set<std::string>::const_iterator it = m_allowedOrigins.begin();
         it != m_allowedOrigins.end(); ++it)
      {
      if (origin.find(*it) == 0)
        {
        return true;
        }
      }
    return false;
    }

  return true;
}

void webSocketServer::SetOriginValidationMode(OriginValidationMode mode) {
  m_originValidationMode = mode;
}

void webSocketServer::AddAllowedOrigin(const std::string& origin) {
  m_allowedOrigins.insert(origin);
}

void webSocketServer::ClearAllowedOrigins() {
  m_allowedOrigins.clear();
}

void webSocketServer::SetMaxHttpFileSize(size_t maxBytes) {
  m_maxHttpFileSize = maxBytes;
}

size_t webSocketServer::GetMaxHttpFileSize() const {
  return m_maxHttpFileSize;
}
