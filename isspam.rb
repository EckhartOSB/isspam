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

  # Connect to (or create) a Bayesian database
  #
  # database is the path to the SQLite database
  def initialize(database)
    newdb = !File.exists?(database)
    @db = SQLite3::Database.new(database)
    if newdb
      query("create table SPAMSTATS (
	    phrase VARCHAR(256) NOT NULL PRIMARY KEY,
	    spam BIGINT DEFAULT 0,
	    good BIGINT DEFAULT 0
	    );")
      # special '' key for total number of each
      query("insert into SPAMSTATS
      		   values (?, 0, 0)", TOTAL_KEY)
    end
    @word_split = /[.:;,]*[\s\n\r\v]+/
    @trailing = /([!?])$/
    @max_phrase_length = 3
  end

private
  TOTAL_KEY = ' '			# Key for totals record

  def retry_query(count, cmd, *args)
    begin
      @db.execute(cmd, args)
    rescue SQLite3::BusyException => e
      raise e if (count < 1)
      sleep 2
      retry_query(count-1, cmd, *args)
    end
  end

  def query(cmd, *args)
    retry_query(30, cmd, args)
  end

  def add_one(row, spam)
    if (spam)
      row[1] = row[1].to_i + 1
    else
      row[2] = row[2].to_i + 1
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
    phrases.uniq.each do |phrase|
      yield phrase
    end
  end

  def add(message, spam)
    @db.transaction do |db|
      each_phrase(message) do |phrase|
	rows = query("select * from SPAMSTATS where phrase = ?", phrase)
	if rows && rows.size > 0
	  row = add_one(rows[0], spam)
	  query("update SPAMSTATS
		    set spam=?, good=?
		    where phrase = ?",
		    row[1], row[2], row[0])
	else
	  row = add_one([phrase, 0, 0], spam)
	  query("insert into SPAMSTATS
		    values (?, ?, ?)", row)
	end
      end
      rows = query("select * from SPAMSTATS where phrase = ?", TOTAL_KEY)
      row = add_one(rows[0], spam)
      query("update SPAMSTATS
    		set spam=?, good=?
		where phrase = ?",
		row[1], row[2], TOTAL_KEY)
    end
  end

  def probability(b, g, nb, ng)
    bp = b / nb
    bp = 1.0 if bp > 1.0
    gp = g / ng
    gp = 1.0 if gp > 1.0
    p = bp / (bp + gp)
    p = 0.01 if p < 0.01
    p = 0.99 if p > 0.99
    p
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
    rows = query("select * from SPAMSTATS where phrase = ?", TOTAL_KEY)
    row = rows[0]
    nb = row[1].to_f	    # total spam messages
    ng = row[2].to_f        # total nonspam messages
    raise "Cannot compute probability: sample too small" if ((nb < 1) || (ng < 1))
    each_phrase(message) do |phrase|
      rows = query("select * from SPAMSTATS where phrase = ?", phrase)
      if rows && rows.size > 0
	row = rows[0]
	b = row[1].to_f
	g = row[2].to_f
	if ((b + g) >= 5)
	  probs << probability(b, g, nb, ng)
	end
      end
    end
    if probs.length > 0
      probs = probs.sort {|a,b| (b - 0.5).abs <=> (a - 0.5).abs}[0,15]	# descending by distance from 0.5
      prod = probs.inject(1) {|t,i| t * i}
      prod / (prod + probs.inject(1){|t,i| t * (1.0 - i)})
    else
      0.5
    end
  end

  # Returns string array of all database information
  def dump(file=$stderr)
    nb = 1.0
    ng = 1.0
    rows = query("select * from SPAMSTATS where phrase = ?", TOTAL_KEY)
    if rows.size > 0
      row = rows[0]
      nb = row[1].to_f
      ng = row[2].to_f
    end
    spammiest = {:prob => 0.0, :occur => 0, :phrases => []}
    cleanest = {:prob => 1.0, :occur => 0, :phrases => []}
    rows = query("select * from SPAMSTATS where phrase <> ? order by phrase", TOTAL_KEY)
    file.puts "Phrase                                             # Spam             # OK  Prob"
    file.puts "------                                             ------             ----  ----"
    rows.each do |phrase, spam, good|
      b = spam.to_i
      g = good.to_i
      if (b + g) >= 5
	p = probability(b, g, nb, ng)
	file.puts sprintf("%-40s %18d %18d %3.3f", phrase[0,40], b, g, p)
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
        file.puts sprintf("%-40s %18d %18d  N/S", phrase[0,40], b, g)
      end
    end
    file.puts ""
    file.puts sprintf("%-40s %16d %16d", "Total messages:", nb, ng)
    file.puts "Phrases: #{rows.size}"
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
    rows = query("select * from SPAMSTATS where phrase = ?", TOTAL_KEY)
    if (rows && rows.size > 0)
      spam = rows[0][1].to_i
      good = rows[0][2].to_i
      total = spam + good
    else
      good = spam = total = nil
    end
    rows = query("select count(*) from SPAMSTATS")
    if (rows && rows.size > 0)
      phrases = rows[0][0].to_i - 1	# subtract totals record
    else
      phrases = nil
    end
    {:phrases => phrases, :total => total, :spam => spam, :good => good }
  end

end
