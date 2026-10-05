require "./elf/*"
require "./agent/*"
require "./common/*"

# Initialize Dark Agent (server mode by default)
log_debug("Starting Dark Agent...")
agent = Dark::Agent::Base.new
agent.run