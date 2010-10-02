require 'rubygems'
require 'bud'
require 'test/unit'
require 'test/test_lib'

require 'lib/kvs'
require 'lib/kvs_metered'

class TestKVS < TestLib

  def add_members(b, *hosts)
    hosts.each do |h|
      print "ADD MEMBER: #{h.inspect}\n"
      assert_nothing_raised(RuntimeError) { b.member << [h] }
    end
  end

  def ntest_wl2
    v = BudKVS.new("localhost", 12347)
    assert_nothing_raised(RuntimeError) {v.run_bg}
    sleep 1
    add_members(v, "localhost:12347", "localhost:12348")
    if v.is_a?  ReliableDelivery
      sleep 1
      workload1(v)
      assert_equal(0, v.bigtable.length)
    end
    
  end

  def ntest_wl3
    v = MeteredKVS.new("localhost", 12350)
    assert_nothing_raised(RuntimeError) {v.run_bg}
    add_members(v, "localhost:12350")
    workload1(v)

    assert_equal(1, v.bigtable.length)
    assert_equal("bak", v.bigtable.first[1])
  end


  def test_wl4
    v = MeteredKVS.new("localhost", 12351)
    assert_nothing_raised(RuntimeError) {v.run_bg}
    add_members(v, "localhost:12351")
    workload2(v)

    soft_tick(v)
    soft_tick(v)
    soft_tick(v)

    assert_equal(1, v.bigtable.length)
    assert_equal("bak", v.bigtable.first[1])
  end


  def ntest_wl1
    v = BudKVS.new("localhost", 12345)
    v2 = BudKVS.new("localhost", 12346)
    assert_nothing_raised(RuntimeError) {v.run_bg}
    assert_nothing_raised(RuntimeError) {v2.run_bg}
    add_members(v, "localhost:12345", "localhost:12346")
    add_members(v2, "localhost:12345", "localhost:12346")
    sleep 1

    workload1(v)

    assert_equal(1, v.bigtable.length)
    assert_equal("bak", v.bigtable.first[1])

    assert_equal(1, v2.bigtable.length)
  end


  def workload1(v)
    # note that this naive key-value store will throw an error if we try to insert
    # two conflicting keys in the same timestep.  below, we ensure that we control
    # the order in which they appear.
    send_channel(v.ip, v.port, "kvstore", ["#{v.ip}:#{v.port}", "localhost:54321", "foo", 1, "bar"])
    soft_tick(v)
    send_channel(v.ip, v.port, "kvstore", ["#{v.ip}:#{v.port}", "localhost:54321", "foo", 2, "baz"])
    soft_tick(v)
    send_channel(v.ip, v.port, "kvstore", ["#{v.ip}:#{v.port}", "localhost:54321", "foo", 3, "bam"])
    soft_tick(v)
    send_channel(v.ip, v.port, "kvstore", ["#{v.ip}:#{v.port}", "localhost:54321", "foo", 4, "bak"])
    soft_tick(v)
    soft_tick(v)
    soft_tick(v)
  end


  def workload2(v)
    send_channel(v.ip, v.port, "kvstore", ["#{v.ip}:#{v.port}", "localhost:54321", "foo", 1, "bar"])
    send_channel(v.ip, v.port, "kvstore", ["#{v.ip}:#{v.port}", "localhost:54321", "foo", 2, "baz"])
    send_channel(v.ip, v.port, "kvstore", ["#{v.ip}:#{v.port}", "localhost:54321", "foo", 3, "bam"])
    send_channel(v.ip, v.port, "kvstore", ["#{v.ip}:#{v.port}", "localhost:54321", "foo", 4, "bak"])
    #soft_tick(v)
    #soft_tick(v)
    #soft_tick(v)
  end
  
  
end
