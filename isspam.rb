# A Bayesian spam filter
#
# Chip Camden, July 2010
#
require 'rubygems'
require 'sqlite3'

# A Bayesian spam filter with a SQLite back-end
class IsSpam

  # Where to split words (Regexp)
  attr :word_split, true

  # Regexp describing trailing trimmable characters
  attr :trailing, true

  # Maximum number of adjacent words to test together
  attr :max_phrase_length, true

  # Maximum number of most significant phrases to consider (0-based, default 15, -1 = use all)
  attr :max_significant, true

  # Maximum number of retries on busy resource (default 60)
  attr :retries, true

  # Interval between retries (in seconds, default 5)
  attr :retry_interval, true

  # Block to handle progress updates
  attr :progress_callback, true

  # Connect to (or create) a Bayesian database
  #
  # database is the path to the SQLite database
  def initialize(database)
    newdb = !File.exists?(database)
    @db = SQLite3::Database.new(database)
    @retries = 60
    @retry_interval = 5
    @db.busy_handler() do |resource, retries|
      if retries && (retries >= @retries)
	@progress_callback.call "Database busy timed out." if @progress_callback
        0
      else
	@progress_callback.call "Database busy...retry #{retries+1}/#{@retries}" if @progress_callback
	sleep @retry_interval
	1
      end
    end
    if newdb
      @db.execute("create table SPAMSTATS (
	    phrase VARCHAR(256) NOT NULL PRIMARY KEY,
	    spam BIGINT NOT NULL DEFAULT 0,
	    good BIGINT NOT NULL DEFAULT 0
	    );")
      @db.execute("create table TOTALS (
	    id INT NOT NULL PRIMARY KEY,
	    spam BIGINT NOT NULL DEFAULT 0,
	    good BIGINT NOT NULL DEFAULT 0
            );")
      @db.execute("insert into TOTALS (id, spam, good)
      		   values (0, 0, 0)")
    else
      begin
        trow = @db.get_first_row("select spam,good from TOTALS where id = 0")
      rescue SQLite3::SQLException
	@db.execute("create table TOTALS (
	      id INT NOT NULL PRIMARY KEY,
	      spam BIGINT NOT NULL DEFAULT 0,
	      good BIGINT NOT NULL DEFAULT 0
	      );")
	# old totals row
        spam, good = @db.get_first_row("select spam, good from SPAMSTATS where phrase = ' '")
	@db.execute("insert into TOTALS (id, spam, good)
		     values (0, ?, ?)", [spam, good]) 
        @db.execute("delete from SPAMSTATS where phrase = ' '")
      end

    end
    @word_split = /[.:;,]*[\s\n\r\v]+/
    @trailing = /([!?])$/
    @max_phrase_length = 3
    @max_significant = 15
    @progress_callback = nil
  end

private
  def add_one(row, spam)
    if (spam)
      row[0] = row[0].to_i + 1
    else
      row[1] = row[1].to_i + 1
    end
    row
  end

  def each_phrase(message)
    msg = message.downcase
    words = msg.split(@word_split).reject {|e| e.length < 1}
    phrases = []
    (1..@max_phrase_length).each do |n|
      (0..(words.size-n)).each do |i|
        phrase = words[i,n].join ' '
	phrases << phrase if phrase.length <= 256
	while (phrase.length > 1) && (trailing =~ phrase)
	  phrase.chomp! $1
	  phrases << phrase	# buy!!, buy!, buy
	end
      end
    end
    # now get any words imbedded with non-word characters
    phrases.concat msg.split(/\W/).reject {|e| e.length < 1}
    cnt = 0
    phrases.uniq!
    phrases.each do |phrase|
      cnt += 1
      @progress_callback.call "Phrase #{cnt}/#{phrases.size}" if @progress_callback
      yield phrase
    end
  end

  def add(message, spam)
    @db.transaction do |db|
      s = @db.prepare "select spam,good from SPAMSTATS where phrase = ?"
      u = @db.prepare "update SPAMSTATS set spam=?, good=? where phrase = ?"
      i = @db.prepare "insert into SPAMSTATS (phrase,spam,good) values (?,?,?)"
      each_phrase(message) do |phrase|
	rows = s.execute! phrase
	if rows.size > 0
	  row = add_one(rows[0], spam)
	  u.execute row[0], row[1], phrase
	else
	  row = add_one([0,0], spam)
	  i.execute phrase, row[0], row[1]
	end
      end
      row = add_one(@db.get_first_row("select spam,good from TOTALS where id = 0"), spam)
      @db.execute("update TOTALS set spam=?, good=?  where id = 0", row)
    end
  end

  def probability(b, g, nb, ng)
    if (b + g) >= 5
      bp = b / nb
      bp = 1.0 if bp > 1.0
      gp = g / ng
      gp = 1.0 if gp > 1.0
      p = bp / (bp + gp)
      p = 0.01 if p < 0.01
      p = 0.99 if p > 0.99
      p
    end
  end

public
  # Message is spam, update database accordingly
  def yes(message)
    add message, true
    nil
  end

  # Message is not spam, update database accordingly
  def no(message)
    add message, false
    nil
  end

  # Is message spam?  Returns probability (0.0 - 1.0)
  def well?(message)
    probs = []
    row = @db.get_first_row("select spam,good from TOTALS where id = 0")
    nb = row[0].to_f	    # total spam messages
    ng = row[1].to_f        # total nonspam messages
    raise "Cannot compute probability: sample too small" if ((nb < 1) || (ng < 1))
    s = @db.prepare "select spam, good from SPAMSTATS where phrase = ?"
    each_phrase(message) do |phrase|
      s.execute! phrase do |row|
	b = row[0].to_f
	g = row[1].to_f
	p = probability(b, g, nb, ng)
	probs << p if p
      end
    end
    if probs.length > 0
      probs = probs.sort {|a,b| (b - 0.5).abs <=> (a - 0.5).abs}[0..@max_significant]	# descending by distance from 0.5
      prod = probs.inject(1) {|t,i| t * i}
      prod / (prod + probs.inject(1){|t,i| t * (1.0 - i)})
    else
      0.5
    end
  end

  # Dump all database information and statistics to file
  def dump(file=$stdout)
    nb = 1.0
    ng = 1.0
    row = @db.get_first_row("select spam,good from TOTALS where id = 0")
    nb = row[0].to_f
    ng = row[1].to_f
    spammiest = {:prob => 0.0, :occur => 0, :phrases => []}
    cleanest = {:prob => 1.0, :occur => 0, :phrases => []}
    file.puts "Phrase                                             # Spam             # OK  Prob"
    file.puts "------                                             ------             ----  ----"
    sign = 0
    count = 0
    @db.execute("select * from SPAMSTATS order by phrase") do |phrase, spam, good|
      count += 1
      b = spam.to_f
      g = good.to_f
      p = probability(b, g, nb, ng)
      if p
        sign += 1
	file.puts sprintf("%-40s %16d %16d %3.3f", phrase[0,40], b, g, p)
	o = b + g
	case p <=> cleanest[:prob]
	  when -1
	    cleanest[:prob] = p
	    cleanest[:occur] = o
	    cleanest[:phrases] = [phrase]
	  when 0
	    case o <=> cleanest[:occur]
	      when 1
	        cleanest[:occur] = o
		cleanest[:phrases] = [phrase]
	      when 0
	        cleanest[:phrases] << phrase
	    end
	end
	case p <=> spammiest[:prob]
	  when 1
	    spammiest[:prob] = p
	    spammiest[:occur] = o
	    spammiest[:phrases] = [phrase]
	  when 0
	    case o <=> spammiest[:occur]
	      when 1
	        spammiest[:occur] = o
		spammiest[:phrases] = [phrase]
	      when 0
	        spammiest[:phrases] << phrase
	    end
	end
      else
        file.puts sprintf("%-40s %16d %16d  N/S", phrase[0,40], b, g)
      end
    end
    file.puts ""
    file.puts sprintf("%-40s %16d %16d", "Total messages:", nb, ng)
    file.puts "Phrases: #{count}    Significant: #{sign} (#{sign*100/count}%)"
    file.puts "Spammiest phrases (#{sprintf("%3.3f", spammiest[:prob])}, #{spammiest[:occur]} occurences):"
    file.puts "\t" + spammiest[:phrases].join("\n\t")
    file.puts " Cleanest phrases (#{sprintf("%3.3f", cleanest[:prob])}, #{cleanest[:occur]} occurences):"
    file.puts "\t" + cleanest[:phrases].join("\n\t")
    nil
  end

  # Returns a hash of statistics for the database
  #
  #  {:phrases => (number of phrases),
  #   :total => (number of messages),
  #   :spam => (number of spam messages),
  #   :good => (number of good messages)}
  def stats
    trow = @db.get_first_row("select spam,good from TOTALS where id = 0")
    spam = trow[0].to_i
    good = trow[1].to_i
    total = spam + good
    trow = @db.get_first_row("select count(phrase) from SPAMSTATS")
    phrases = trow[0].to_i
    {:phrases => phrases, :total => total, :spam => spam, :good => good }
  end

  # Yields detailed statistics for each phrase in the input
  def phrase_stats(words)
    trow = @db.get_first_row("select spam,good from TOTALS where id = 0")
    nb = trow[0].to_i
    ng = trow[1].to_i
    s = @db.prepare "select spam,good from SPAMSTATS where phrase = ?"
    each_phrase(words) do |phrase|
      spam = 0
      good = 0
      s.execute! phrase do |row|
        spam = row[0].to_f
	good = row[1].to_f
      end
      score = probability(spam, good, nb, ng)
      yield phrase, spam, good, score
    end
  end

  # Set the progress_callback to the block passed
  def onprogress(&block)
    @progress_callback = block
  end

end
