#!/usr/bin/env ruby
require 'readline'
require 'rubygems'
require 'bud'
require 'abbrev'

TABLE_TYPES = ["table", "scratch", "channel", "loopback", "periodic", "sync", "store"]

# The class to which rebl adds user-specified rules and declarations.
class ReblClass
  include Bud
  attr_accessor:port, :ip

  # Support for breakpoints
  state { scratch :rebl_breakpoint }
end


# Static class that contains constants and functions for the rebl shell.
class ReblShell
  @@histfile = File::expand_path("~/.rebl_history")
  @@maxhistsize = 100
  @@escape_char = '/'
  @@commands =
    {"tick" => [lambda {|lib,argv| lib.tick([Integer(argv[1]), 1].max)},
                "tick [x]:\texecutes x (or 1) timesteps"],

    "run" => [lambda {|lib,_| lib.run},
              "run:\ttick until quiescence, a breakpoint, or #{@@escape_char}stop"],

    "stop" => [lambda {|lib,_| lib.stop},
               "stop:\tstop ticking"],

    "lsrules" => [lambda {|lib,_| lib.rules.sort{|a,b| a[0] <=> b[0]}.each {|k,v| puts "#{k}: "+v}},
                  "lsrules:\tlist rules"],

    "rmrule" => [lambda {|lib,argv| lib.del_rule(Integer(argv[1]))},
                 "rmrule x:\tremove rule number x"],

    "lscollections" => [lambda {|lib,_| lib.state.sort{|a,b| a[0] <=> b[0]}.each {|k,v| puts "#{k}: "+v}},
                        "lscollections:\tlist collections"],

    "dump" => [lambda {|lib,argv| lib.dump(argv[1])},
               "dump c:\tdump contents of collection c"],

    "exit" => [lambda {|_,_| do_exit}, "exit:\texit rebl"],

    "quit" => [lambda {|_,_| do_exit}, "quit:\texit rebl"],

    "help" => [lambda {|_,_| pretty_help},
               "help:\tprint this help message"]}
  @@abbrevs = @@commands.keys.abbrev
  @@exit_message = "Rebellion quashed."

  # Starts a rebl shell.
  #--
  # This function is not covered by testcases, but setup
  # and rebl_loop are.
  #++
  def self.run
    lib = setup
    loop do
      begin
        rebl_loop(lib)
      rescue Exception
        puts "exception: #{$!}"
      end
    end
  end

  # Performs setup as part of starting a rebl shell, and returns the instance of
  # LibRebl that is created; testcases call this directly.
  def self.setup
    ipport = ARGV[0] ? ARGV[0].split(":") : []
    lib = LibRebl.new(*[(ipport[0] or "localhost"), (ipport[1] or 0)])
    setup_history

    comp = proc do |s|
      @@commands.keys.map do |c|
        @@escape_char+c
      end.grep( /^#{Regexp.escape(s)}/ )
    end
    Readline.completion_append_character = ' '
    Readline.completion_proc = comp

    welcome
    return lib
  end

  # One step of the rebl shell loop: processes one rebl shell line from stdin
  # and returns.  May raise an Exception.
  def self.rebl_loop(lib, noreadline=false)
    begin
      if noreadline
        line = gets
      else
        line = Readline::readline('rebl> ')
      end
      do_exit if line.nil?
      puts line unless $stdin.tty?
      line.strip!
      return if line.empty? or line[0..0] == "#"
      Readline::HISTORY.push(line) unless noreadline
      split_line = line.split(" ")
      if line[0..0] == @@escape_char then
        # Command
        split_line[0].slice! 0
        if command split_line[0]
          command(split_line[0]).call(lib, split_line)
        else
          puts "invalid command or ambiguous command prefix"
        end
      elsif TABLE_TYPES.include? split_line[0]
        # Collection
        lib.add_collection(line)
      else
        # Rule
        lib.add_rule(line)
      end
    rescue Interrupt
      abort(do_exit)
    end
  end

  # Reads permanent history from @@histfile.  This code is pretty much the same
  # as irb's code.
  def self.setup_history
    begin
      if File::exists?(@@histfile)
        lines = IO::readlines(@@histfile).collect { |line| line.chomp }
        Readline::HISTORY.push(*lines)
      end
    rescue Exception
      puts "Error when configuring permanent history: #{$!}"
    end
  end

  # lookup full command from abbreviation
  def self.command(c)
    return @@abbrevs[c].nil? ? nil : @@commands[@@abbrevs[c]][0]
  end

  private
  # pretty-printed help
  def self.pretty_help
    puts "rebl commands are prefixed by '#{@@escape_char}'"
    puts "other input is interpreted as Bloom code."
    puts
    puts "rebl commands:"
    maxlen = @@commands.keys.sort{|a,b| b.size - a.size}.first.size
    cmd_list = @@commands.keys.sort
    cmd_list.each do |c|
      v = @@commands[c]
      puts @@escape_char +
        v[1].gsub(/\t/, " "*(maxlen + 3 - v[1].split(':')[0].size))
    end
    puts "\nbreakpoints:"
    puts "a breakpoint is a rule with the 'breakpoint' scratch on the left of "+
      "a '<=' operator.\n'#{@@escape_char}run' will stop ticking at the end of a "+
      "timestep where a 'breakpoint' tuple exists."
  end

  private
  def self.welcome
    puts "Welcome to rebl, the interactive Bloom terminal."
    puts
    puts "Type: " + @@escape_char + "h for help"
    puts "      " + @@escape_char + "q to quit"
    puts
  end

  private
  # Called on exit.  Writes the session's history to @@histfile, and stops the
  # bud instance from listening.
  def self.do_exit
    begin
      lines = Readline::HISTORY.to_a.reverse.uniq.reverse
      lines = lines[-@@maxhistsize, @@maxhistsize] if lines.nitems>@@maxhistsize
      File::open(@@histfile, File::WRONLY|File::CREAT|File::TRUNC) do |io|
        io.puts lines.join("\n")
      end
    rescue Exception
      puts "Error when saving permanent history: #{$!}"
    end
    @rebl_class_inst.stop_bg if @rebl_class_inst
    puts "\n" + @@exit_message
    exit!(0)
  end
end


# Library of functions used by rebl.  More generally, this can be viewed as a
# way to have a bud class that you can add and remove rules from, and that you
# can step through the execution of.
class LibRebl
  attr_accessor :rules, :state
  attr_reader :ip, :port, :rebl_class_inst
  @@builtin_tables = [:stdio, :t_depends, :periodics_tbl, :t_cycle, :localtick,
                      :t_provides, :t_rules, :t_depends_tc, :t_stratum,
                      :rebl_breakpoint]

  def initialize(ip, port)
    @ip = ip
    @port = port
    @rules = {}
    @ruleid = 0
    @state = {}
    @stateid = 0
    @rebl_class = nil
    @rebl_class_inst = nil
    @old_inst = nil
    reinstantiate
  end

  # Runs the bud instance (until a breakpoint, or stop() is called)
  def run
    @rebl_class_inst.sync_do {@rebl_class_inst.lazy = false}
  end

  # Stops the bud instance (and then performs another tick)
  def stop
    @rebl_class_inst.sync_do {@rebl_class_inst.lazy = true}
  end

  # Ticks the bud instance a specified integer number of times.
  def tick(x)
    x.times {@rebl_class_inst.sync_do}
  end

  # Dumps the contents of a table at the current time.
  def dump(c)
    tups = @rebl_class_inst.instance_eval("#{c}.inspected")
    puts(tups.empty? ? "(empty)" : tups.sort.join("\n"))
  end

  # Declares a new collection.
  def add_collection(c)
    @state[@stateid += 1] = c
    begin
      reinstantiate
    rescue Exception
      @state.delete(@stateid)
      raise
    end
  end

  # Deactivates a rule at the current time; any tuples derived by the rule at
  # a previous time are still available.
  def del_rule(rid)
    @rules.delete(rid)
    reinstantiate
  end

  # Adds a new rule at the current time; only derives tuples based on data that
  # exists at the current or a future time.
  def add_rule(r)
    @rules[@ruleid += 1] = r
    begin
      reinstantiate
    rescue Exception
      @rules.delete(@ruleid)
      raise
    end
  end

  private
  def reinstantiate
    # New anonymous subclass.
    @rebl_class = Class.new(ReblClass)

    begin
      if not @rules.empty?
        @rebl_class.class_eval("bloom :rebl_rules do\n" +
                               @rules.sort.map {|_,r| r}.join("\n") + "\nend")
      end
      if not @state.empty?
        @rebl_class.class_eval("state do\n" + @state.values.join("\n") + "\nend")
      end
    rescue Exception
      raise
    end

    @old_inst = @rebl_class_inst
    @rebl_class_inst = @rebl_class.new(:signal_handling => :none, :ip => @ip,
                                       :port => @port, :lazy => true)

    # Copy the tables over.
    if @old_inst
      @rebl_class_inst.tables.merge!(@old_inst.tables.reject do |k,v|
                                       @@builtin_tables.include? k
                                     end)
      @rebl_class_inst.channels.merge!(@old_inst.channels.reject do |k,v|
                                         @@builtin_tables.include? k
                                       end)
      @rebl_class_inst.tc_tables.merge! @old_inst.tc_tables
      @rebl_class_inst.dbm_tables.merge! @old_inst.dbm_tables
      @rebl_class_inst.zk_tables.merge! @old_inst.zk_tables

      # Fix the bud instance pointers from copied tables.
      @rebl_class_inst.tables.values.each do |v|
        v.bud_instance = @rebl_class_inst
      end
    end

    # Run lazily in background, shutting down old instance.
    begin
      @old_inst.stop_bg if @old_inst
      # Lazify the instance upon a breakpoint (no effect if instance is
      # already lazy)
      @rebl_class_inst.register_callback(:rebl_breakpoint) do
        @rebl_class_inst.lazy = true
      end
      @rebl_class_inst.run_bg
      @ip = @rebl_class_inst.ip
      @port = @rebl_class_inst.port
      puts "Listening on #{@rebl_class_inst.ip_port}" if not @old_inst
    rescue Exception
      # The above two need to be atomic, or we're in trouble.
      puts "unrecoverable error, please file a bug: #{$!}"
      abort
    end
  end
end
