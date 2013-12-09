import os
import json
import random
from collections import namedtuple
from operator import itemgetter

json_transactions = open('../../Debug/transactions.json').read()
json_syscalls = open('../../Debug/syscalls.json').read()

transactions = {}
transactions_s = json.loads(json_transactions)
syscalls = json.loads(json_syscalls)

###############################################################################
# CONSTANTS, TABLES AND HELPER FUNCTIONS
###############################################################################
# I/O fd type
FD_TYPE_FILE = 1
FD_TYPE_NET = 2
FD_TYPE_FILE_NET = FD_TYPE_FILE | FD_TYPE_NET

# Number of entries in the sorted datasets
TOPX_NENTRIES_TREEMAP = 50
TOPX_NENTRIES_PIE = 15

# List of calls that we want to categorize as "file/network I/O"
iocalls = ['read', 'write', 'open', 'accept', 'close', 'llseek', 'lseek', 'readv', 'writev']

# Subset of the I/O calls that have to do with reading or writing actual data
data_iocalls = ['read', 'write', 'readv', 'writev']

# List of calls that we want to categorize as "wait"
# NOTE: poll is not here because we already thread it in a specific way
waitcalls = ['select', 'newselect', 'futex', 'nanosleep', 'waitpid', 'newselect', 'nanosleep', 'ipc']

class SysRtrExcep(RuntimeError):
   def __init__(self):
      pass
      
#
# Find the transaction that a pid is serving at a given time
# XXX this currently returns only a single transaction. If more than one transaction matches, the 
# first match is returned
#
def lookup_transaction(pid, time):
  tpid = transactions.get(pid)
  
  if tpid != None:
    for tr in tpid:
      if time >= tr['is'] and time <= tr['oe']:
        return tr
      
  return None

#
# Navigate the chain of peers starting from a transaction, looking for a given peer
#
def navigate_transactions(srctr, targettr):
  srcpid = srctr['rproc']['pid']

  targetpid = transactions.get(srcpid)
      
  if targetpid != None:
    for tr in targetpid:
      if  tr == targettr:
        return True
      else:
        return navigate_transactions(tr, targettr)        
  else:
    return False

#
# Restructure the transaction table for internal use.
# NOTE: json doesn't support numeric keys, therefore we translate the transaction table
# by scanning it. We'll access it a lot, so we want it to be efficient.
#
def refactor_transactions():
  for t in transactions_s:
    pidentry = transactions_s[t]
    for transentry in pidentry:
      transentry['f'] = {'n': 0, 't': 0, 'e': 0, 's': 0} # files
      transentry['r'] = {'n': 0, 't': 0, 'e': 0, 's': 0} # network
      transentry['u'] = {'n': 0, 't': 0, 'e': 0, 's': 0} # uncategorized syscalls
      transentry['p'] = {'n': 0, 't': 0, 'e': 0, 's': 0} # processing
      transentry['w'] = {'n': 0, 't': 0, 'c':{FD_TYPE_FILE:{'n': 0, 't': 0}, FD_TYPE_NET:{'n': 0, 't': 0}, FD_TYPE_FILE_NET:{'n': 0, 't': 0}}} # I/O wait
    
    transactions[int(t)] = pidentry
  
###############################################################################
# STATE FOR THE ioparser CLASS
###############################################################################
class ioparser_state:
  def __init__(self):
    self.start_time = 0
    self.end_time = 0
    self.ncalls = 0
    self.files = {}
    self.conns = {}
    self.procs_files = {}
    self.procs_conns = {}
    self.uncategorized_syscalls = {}
    self.procs_uncategorized = {}
    self.procs_processing = {}
    self.procs_iowait = {}
    self.fileio_counter = {'n': 0, 't': 0, 'e': 0, 's': 0}
    self.networkio_counter = {'n': 0, 't': 0, 'e': 0, 's': 0}
    self.iowait_counter = {'n': 0, 't': 0, 'c':{FD_TYPE_FILE:{'n': 0, 't': 0}, FD_TYPE_NET:{'n': 0, 't': 0}, FD_TYPE_FILE_NET:{'n': 0, 't': 0}}}
    self.uncategorized_counter = {'n': 0, 't': 0, 'e': 0, 's': 0}
    self.processing_counter = {'n': 0, 't': 0, 'e': 0, 's': 0}

###############################################################################
# I/O REPORTER CLASS
###############################################################################
class ioparser:
  ios = {}
  gaps = {}
  wait_syscalls = {}
  uncategorized_syscalls = {}
  
  gstate = ioparser_state()
  urlstates = {}
  agentstates = {}
  
  #
  # Push an operation's info into a table entry
  #
  def table_add(self, table, fname, delta, size=0):
    entry = table.get(fname)
    if entry == None:
      table[fname] = {'n': 1, 't': delta, 'e': 0, 's': size}
    else:
      entry['n'] += 1
      entry['t'] += delta
      entry['s'] += size
      
  #
  # Push an error into a table entry
  #
  def table_error_add(self, table, fname, delta):
    entry = table.get(fname)
    if entry == None:
      table[fname] = {'n': 1, 't': delta, 'e': 1, 's': 0}
    else:
      entry['n'] += 1
      entry['t'] += delta
      entry['e'] += 1
      
  #
  # Push an operation's info into a counter
  #
  def counter_add(self, counter, delta, size=0):
      counter['n'] += 1
      counter['t'] += delta
      counter['s'] += size
      
  #
  # Push an operation's info into a counter
  #
  def counter_error_add(self, counter, delta):
      counter['n'] += 1
      counter['t'] += delta
      counter['e'] += 1
      
  #
  # Push an entry into a 2-level table
  #
  def table_2level_add(self, table, parentname, childname, delta, size=0, errors = 0):
    entry = table.get(parentname)
    if entry == None:
      newentry = {'n': 1, 's': size, 't': delta, 'e': errors, 'c':{childname:{'n': 1, 's': size, 't': delta, 'e': errors}}}
      table[parentname] = newentry
    else:
      entry['n'] += 1
      entry['t'] += delta
      entry['s'] += size
      entry['e'] += errors
      
      callentry = entry['c'].get(childname)
      if callentry == None:
        entry['c'][childname] = {'n': 1, 's': size, 't': delta, 'e': errors}
      else:
        callentry['n'] += 1
        callentry['t'] += delta
        callentry['s'] += size
        callentry['e'] += errors
      
  #
  # Push a write wait event
  #
  def add_process_iowait(self, table, procname, type, delta):
    entry = table.get(procname)
    if entry == None:
      table[procname] = {'n': 1, 't': delta, 'c':{type:{'n': 1, 't': delta}}}
    else:
      entry['n'] += 1
      entry['t'] += delta

      typeentry = entry['c'].get(type)
      if typeentry == None:
        entry['c'][type] = {'n': 1, 't': delta}
      else:
        typeentry['n'] += 1
        typeentry['t'] += delta

  #
  # Push an operation's info into a counter
  #
  def counter_iowait_add(self, counter, type, delta):
      counter['n'] += 1
      counter['t'] += delta
      subcounter = counter['c'][type]
      subcounter['n'] += 1
      subcounter['t'] += delta
      
  #
  # Processing entry point
  #    
  def run(self):
    for s in syscalls:
      name = s['name']
      pid = s['pid']
      ts = s['ts']
      direction = s['dir']
      cname = s['name']
      if cname == 'syscall':
        cname = s['pars']['name']['v']
      
      #
      # If this event is inside a transaction, find the transaction
      #
      agent = None
      trans = lookup_transaction(pid, ts)
      if trans != None:
        #
        # Lookup for the url table entry for this transaction, or create one if there's
        # none there.
        #
        url = trans.get('url')
        if url == None:
          url = 'IP'

        urlstate = self.urlstates.get(url)
        if urlstate == None:
          urlstate = ioparser_state()
          self.urlstates[url] = urlstate
      
        #
        # Lookup for the agent table entry for this transaction, or create one if there's
        # none there.
        #
        agent = trans.get('agent')
        if agent != None:
          agentstate = self.agentstates.get(agent)
          if agentstate == None:
            agentstate = ioparser_state()
            self.agentstates[agent] = agentstate
          
      #
      # Update global counters
      #
      if direction == '<':
        self.gstate.ncalls += 1
      if self.gstate.start_time == 0:
        self.gstate.start_time = ts
      self.gstate.end_time = ts
            
      #
      # Here we measure processing gaps, i.e. time between system calls
      #
      if direction == '<':
          self.gaps[pid] = {'t': ts}
      else:
        entry = self.gaps.get(pid)
        
        if entry != None:
          delta = ts - entry['t']
          self.table_add(self.gstate.procs_processing, s['comm'], delta)
          self.counter_add(self.gstate.processing_counter, delta)
          if trans != None:
            self.table_add(urlstate.procs_processing, s['comm'], delta)
            self.counter_add(urlstate.processing_counter, delta)
          if agent != None:
            self.table_add(agentstate.procs_processing, s['comm'], delta)
            self.counter_add(agentstate.processing_counter, delta)

          del self.gaps[pid]
        
      #
      # Here we measure various system-call related metrics
      #
      if name in iocalls:
        if direction == '>':
          #
          # This is an enter event. We save the timestamp.
          #
          if name == 'open':
            #
            # for open(), we just save ts and name and we'll retrieve the rest in 
            # the exit event
            #
            fname = s['pars']['name']['v']
            self.ios[s['pid']] = {'ts': ts, 'name':fname}
          elif name == 'accept':
            #
            # for accept(), we just save ts
            #
            self.ios[s['pid']] = {'ts': ts}
          else:
            #
            # Every event other than open contains the fd information, so we can 
            # parse it here 
            #
            fd = s['pars']['fd']['v']
            try:
              fname_plus_type = s['pars']['fd']['r']
            except:
              continue
              
            #
            # Filter out anything that is not a file.
            # The first letter in an fd resolved name is the type. fd type letters
            # are defined in scap.h
            #
            fname = fname_plus_type[1:]
            
            if fname_plus_type[0] in ['f', 'p', 'e']:
              self.ios[s['pid']] = {'ts': ts, 'fd':fd, 'name':fname, 'type':FD_TYPE_FILE}
            elif fname_plus_type[0] == '4':
              self.ios[s['pid']] = {'ts': ts, 'fd':fd, 'name':fname, 'type':FD_TYPE_NET}
            else:
              #
              # Unsupported fd type, keep going without adding this operation to the table
              #
              continue
        else:
          #
          # This is an exit event. Time to measure the latency.
          # Information for this process is not here if the currently processed
          # fd is not a file
          #
          ioentry = self.ios.get(s['pid'])
          if ioentry == None:
            #
            # Exit event without the correspondent enter. Prbably caused by a drop.
            #
            continue
          else:
            delta = ts - ioentry['ts']
            
            #
            # open() and accept() have the fd info in the exit event, so we parse it here
            #
            if name == 'open':
              type = FD_TYPE_FILE
              res = int(s['pars']['fd']['v'])
              fname = ioentry.get('name')
              if fname == None:
                # This happens when events are dropped
                continue
            elif name == 'accept':
              type = FD_TYPE_NET
              res = int(s['pars']['fd']['v'])
              fname = s['pars']['tuple']['v']
            else:
              res = int(s['pars']['res']['v'])
              fname = ioentry.get('name')
              if fname == None:
                # This happens when events are dropped
                continue
              type = ioentry['type']
              
            #
            # Che the result
            #              
            if res < 0:
              #
              # Call failed
              #
              if type == FD_TYPE_FILE:
                self.table_error_add(self.gstate.files, fname, delta)
                self.table_2level_add(self.gstate.procs_files, s['comm'], fname, 0, 0, 1)
                self.counter_error_add(self.gstate.fileio_counter, delta)
                if trans != None:
                  self.table_error_add(urlstate.files, fname, delta)
                  self.table_2level_add(urlstate.procs_files, s['comm'], fname, 0, 0, 1)
                  self.counter_error_add(urlstate.fileio_counter, delta)
                if agent != None:
                  self.table_error_add(agentstate.files, fname, delta)
                  self.table_2level_add(agentstate.procs_files, s['comm'], fname, 0, 0, 1)
                  self.counter_error_add(agentstate.fileio_counter, delta)
              elif type == FD_TYPE_NET:
                self.table_error_add(self.gstate.conns, fname, delta)
                self.table_error_add(self.gstate.procs_conns, s['comm'], delta)
                self.counter_error_add(self.gstate.networkio_counter, delta)
                if trans != None:
                  self.table_error_add(urlstate.conns, fname, delta)
                  self.table_error_add(urlstate.procs_conns, s['comm'], delta)
                  self.counter_error_add(urlstate.networkio_counter, delta)
                if agent != None:
                  self.table_error_add(agentstate.conns, fname, delta)
                  self.table_error_add(agentstate.procs_conns, s['comm'], delta)
                  self.counter_error_add(agentstate.networkio_counter, delta)
              else:
                assert False
            else:
              #
              # Call succeeded
              #
              size = 0
              
              #
              # In case of read and write, retrieve the data size
              #
              if name in data_iocalls:
                size = res

              #
              # Update the operation
              #
              if type == FD_TYPE_FILE:
                self.table_add(self.gstate.files, fname, delta, size)
                self.table_2level_add(self.gstate.procs_files, s['comm'], fname, delta, size)
                self.counter_add(self.gstate.fileio_counter, delta, size)
                if trans != None:
                  self.table_add(urlstate.files, fname, delta, size)
                  self.table_2level_add(urlstate.procs_files, s['comm'], fname, delta, size)
                  self.counter_add(urlstate.fileio_counter, delta, size)
                if agent != None:
                  self.table_add(agentstate.files, fname, delta, size)
                  self.table_2level_add(agentstate.procs_files, s['comm'], fname, delta, size)
                  self.counter_add(agentstate.fileio_counter, delta, size)
              elif type == FD_TYPE_NET:
                self.table_add(self.gstate.conns, fname, delta, size)
                self.table_add(self.gstate.procs_conns, s['comm'], delta, size)
                self.counter_add(self.gstate.networkio_counter, delta, size)
                if trans != None:
                  self.table_add(urlstate.conns, fname, delta, size)
                  self.table_add(urlstate.procs_conns, s['comm'], delta, size)
                  self.counter_add(urlstate.networkio_counter, delta, size)
                if agent != None:
                  self.table_add(agentstate.conns, fname, delta, size)
                  self.table_add(agentstate.procs_conns, s['comm'], delta, size)
                  self.counter_add(agentstate.networkio_counter, delta, size)
              else:
                self.table_2level_add(self.gstate.procs_uncategorized, s['comm'], cname, delta)
                self.counter_add(self.gstate.uncategorized_counter, delta)
                if trans != None:
                  self.table_2level_add(urlstate.procs_uncategorized, s['comm'], cname, delta)
                  self.counter_add(urlstate.uncategorized_counter, delta)
                if agent != None:
                  self.table_2level_add(agentstate.procs_uncategorized, s['comm'], cname, delta)
                  self.counter_add(agentstate.uncategorized_counter, delta)
                continue
              

            del self.ios[s['pid']]
      elif name == 'poll':
        #
        # This is a poll
        #
        if direction == '>':
            self.wait_syscalls[pid] = {'t': ts}
        else:
          entry = self.wait_syscalls.get(pid)
          
          if entry == None:
            #
            # This happens often at the beginning of a trace, where events can 
            # be truncated
            #
            continue
          
          delta = ts - entry['t']
          
          #
          # Extract the list of fds and iterate over it
          #
          fds_str = s['pars']['fds']['v']
          fds = fds_str.split(' ')
          type = 0
          skip = False

          for fd in fds:
            fdc = fd.split(':')
            fdtype = fdc[1][0]
            optype = int(fdc[1][1:])
            
            #
            # We don't care about fds that haven't been signalled
            #
            if optype == 0:
              continue
            
            #
            # We want that all the signalled fds are "write" 
            #
            if optype not in (4, 1):
              skip = True
              break
              
            if fdtype in ['f', 'p', 'e']:
              type = type | FD_TYPE_FILE
            elif fdtype == '4':
              type = type | FD_TYPE_NET
            else:
              continue
          
          if type == 0:
            skip = True
            
          if skip:
            self.table_2level_add(self.gstate.procs_uncategorized, s['comm'], cname, delta)
            self.counter_add(self.gstate.uncategorized_counter, delta)
            if trans != None:
              self.table_2level_add(urlstate.procs_uncategorized, s['comm'], cname, delta)
              self.counter_add(urlstate.uncategorized_counter, delta)
            if agent != None:
              self.table_2level_add(agentstate.procs_uncategorized, s['comm'], cname, delta)
              self.counter_add(agentstate.uncategorized_counter, delta)
          else:
            self.add_process_iowait(self.gstate.procs_iowait, s['comm'], type, delta)
            self.counter_iowait_add(self.gstate.iowait_counter, type, delta)
            if trans != None:
              self.add_process_iowait(urlstate.procs_iowait, s['comm'], type, delta)
              self.counter_iowait_add(urlstate.iowait_counter, type, delta)
            if agent != None:
              self.add_process_iowait(agentstate.procs_iowait, s['comm'], type, delta)
              self.counter_iowait_add(agentstate.iowait_counter, type, delta)
          
          del self.wait_syscalls[pid]
      else:
        #
        # This is an uncategorized syscall
        #
        if direction == '>':
          if not s['name'] in waitcalls:
            if s['pars'].get('ID') != None:
              generic_call_name = s['pars']['name']['v']
              if generic_call_name in waitcalls:
                continue
            self.uncategorized_syscalls[pid] = {'t': ts}
        else:
          entry = self.uncategorized_syscalls.get(pid)
          
          if entry == None:
            #
            # This happens often at the beginning of a trace, where events can 
            # be truncated
            #
            self.table_2level_add(self.gstate.procs_uncategorized, s['comm'], cname, 0)
            self.counter_add(self.gstate.uncategorized_counter, 0)
            if trans != None:
              self.table_2level_add(urlstate.procs_uncategorized, s['comm'], cname, 0)
              self.counter_add(urlstate.uncategorized_counter, 0)
            if agent != None:
              self.table_2level_add(agentstate.procs_uncategorized, s['comm'], cname, 0)
              self.counter_add(agentstate.uncategorized_counter, 0)
            continue
          
          delta = ts - entry['t']
            
          self.table_2level_add(self.gstate.procs_uncategorized, s['comm'], cname, delta)
          self.counter_add(self.gstate.uncategorized_counter, delta)
          if trans != None:
            self.table_2level_add(urlstate.procs_uncategorized, s['comm'], cname, delta)
            self.counter_add(urlstate.uncategorized_counter, delta)
          if agent != None:
            self.table_2level_add(agentstate.procs_uncategorized, s['comm'], cname, delta)
            self.counter_add(agentstate.uncategorized_counter, delta)
          
          del self.uncategorized_syscalls[pid]
  
  def emit(self, basedirname, dirname):
    print '****** FILES ******'
    for f in self.gstate.files:
      print '%s - n:%d, s:%d, t:%d, e:%d' % (f, self.gstate.files[f]['n'], self.gstate.files[f]['s'], self.gstate.files[f]['t'], self.gstate.files[f]['e'])

    print '****** CONNECTIONS ******'
    for f in self.gstate.conns:
      print '%s - n:%d, s:%d, t:%d, e:%d' % (f, self.gstate.conns[f]['n'], self.gstate.conns[f]['s'], self.gstate.conns[f]['t'], self.gstate.conns[f]['e'])
      
    print '****** PROCS-FILES ******'
    for p in self.gstate.procs_files:
      entry = self.gstate.procs_files[p]
      print '%s - n:%d, s:%d, t:%d, e:%d' % (p, entry['n'], entry['s'], entry['t'], entry['e'])
      for c in entry['c']:
        print '\t%s - n:%d, s:%d, t:%d, e:%d' % (c, entry['c'][c]['n'], entry['c'][c]['s'], entry['c'][c]['t'], entry['c'][c]['e'])

    print '****** PROCS-CONNECTIONS ******'
    for p in self.gstate.procs_conns:
      print '%s - n:%d, s:%d, t:%d, e:%d' % (p, self.gstate.procs_conns[p]['n'], self.gstate.procs_conns[p]['s'], self.gstate.procs_conns[p]['t'], self.gstate.procs_conns[p]['e'])

    print '****** PROCS-SYSCALLS ******'
    for p in self.gstate.procs_uncategorized:
      entry = self.gstate.procs_uncategorized[p]
      print '%s - n:%d, t:%d' % (p, entry['n'], entry['t'])
      for c in entry['c']:
        print '\t%s - n:%d, t:%d' % (c, entry['c'][c]['n'], entry['c'][c]['t'])
      
    print '****** PROCS-PROCESSING ******'
    for p in self.gstate.procs_processing:
      print '%s - n:%d, t:%d' % (p, self.gstate.procs_processing[p]['n'], self.gstate.procs_processing[p]['t'])

    print '****** PROCS-WAIT ******'
    for p in self.gstate.procs_iowait:
      entry = self.gstate.procs_iowait[p]
      print '%s - n:%d, t:%d' % (p, entry['n'], entry['t'])
      for c in entry['c']:
        print '\t%s - n:%d, t:%d' % (c, entry['c'][c]['n'], entry['c'][c]['t'])
        
    print '****** SUMMARY ******'
    print 'total - n:%d, t:%d' % (self.gstate.ncalls, self.gstate.end_time - self.gstate.start_time)
    print 'file io - n:%d, s:%d, t:%d, e:%d' % (self.gstate.fileio_counter['n'], self.gstate.fileio_counter['s'], self.gstate.fileio_counter['t'], self.gstate.fileio_counter['e'])
    print 'network io - n:%d, s:%d, t:%d, e:%d' % (self.gstate.networkio_counter['n'], self.gstate.networkio_counter['s'], self.gstate.networkio_counter['t'], self.gstate.networkio_counter['e'])
    print 'io wait - n:%d, t:%d' % (self.gstate.iowait_counter['n'], self.gstate.iowait_counter['t'])
    print 'uncategorized - n:%d, t:%d' % (self.gstate.uncategorized_counter['n'], self.gstate.uncategorized_counter['t'])
    print 'processing - n:%d, t:%d' % (self.gstate.processing_counter['n'], self.gstate.processing_counter['t'])
    
    #
    # The real deal json emit
    #
    self.emit_files_json(self.gstate.files, basedirname, dirname, 'allfiles.json')
    self.emit_procs_json(self.gstate, basedirname, dirname)
    self.emit_general_json(self.gstate, basedirname, dirname, 'overview.json')

    # URLs
    try:
      if not os.path.exists(basedirname + '/' + dirname + '/urls'):
        os.mkdir(basedirname + '/' + dirname + '/urls')
    except:
      pass
    for u in self.urlstates:
      us = self.urlstates[u]
      subdirname = basedirname + '/' + dirname + '/urls/' + u
      try:
        os.mkdir(subdirname)
      except:
        pass
      
      self.emit_files_json(us.files, basedirname, dirname + '/urls/' + u + '/', 'allfiles.json')
      self.emit_procs_json(us, basedirname, dirname + '/urls/' + u + '/')
      self.emit_general_json(us, basedirname, dirname + '/urls/' + u + '/', 'overview.json')

    # agents
    try:
      if not os.path.exists(basedirname + '/' + dirname + '/agents'):
        os.mkdir(basedirname + '/' + dirname + '/agents')
    except:
      pass
    for u in self.agentstates:
      us = self.agentstates[u]
      subdirname = basedirname + '/' + dirname + '/agents/' + u
      try:
        os.mkdir(subdirname)
      except:
        pass
      
      self.emit_files_json(us.files, basedirname, dirname + '/agents/' + u + '/', 'allfiles.json')
      self.emit_procs_json(us, basedirname, dirname + '/agents/' + u + '/')
      self.emit_general_json(us, basedirname, dirname + '/agents/' + u + '/', 'overview.json')
      
  #
  # Helper function used to convert a file table into a json representation.
  # used by emit() and emit_procs_json()
  #
  def emit_files_json(self, table, basedirname, dirname, filename):
    if dirname == '':
      fname = basedirname + '/' + filename
    else:
      fname = basedirname + '/' + dirname + '/' + filename
      
    file = open(fname, 'w')

    #
    # Init the data
    #
    data = {
           "hierarchy_level": 1, 
           "name": "Files", 
           "entity_name": ["All Infrastructure"], 
           "show_child_labels": False, 
           "click_target": [
            "data/app-serv01/Network Apps.json", 
            "treemap"
           ], 
           "data_depth": 2, 
           "entity_selection": 0, 
                        
            'metric_selection': 0,
            'entity_alternatives': [
              {'name': 'Overview', 'targetdata':dirname + 'overview.json', 'targetchart':'pie'},
              {'name': 'Process Peers', 'targetdata':dirname + 'graph.json', 'targetchart':'depgraph'},
              {'name': 'Files', 'targetdata':dirname + 'allfiles.json', 'targetchart':'treemap'},
              {'name': 'URLs', 'targetdata':dirname + 'url_overview.json', 'targetchart':'pie'},
              {'name': 'Client Types', 'targetdata':dirname + 'agent_overview.json', 'targetchart':'pie'},
            ],
            'metric_alternatives': [
              ['Total Bytes', 0],
              ['Time', 1],
              ['IOPS', 2],
              ['# Errors', 3],
            ],
            'children': [
            ]
           }
    
    #
    # Add the 'children' section
    #
    sorted_files = sorted(table.keys(), key=lambda f: (-table[f]['s']))
    
    dirdict = {}
    j = 0
    for f in sorted_files:
      if j >= TOPX_NENTRIES_TREEMAP:
        break
      j += 1

      fentry = table[f]
      
      dirpos = f.rfind('/')
      if dirpos != -1:
        dirname = f[:dirpos + 1]
      else:
        dirname = '/'

      entry = {
       'name': f, 
       'l': 1,
       'c0': fentry['s'], 
       'c1': fentry['t'],
       'c2': fentry['n'], 
       'c3': fentry['e'], 
      }
      
      direntry = dirdict.get(dirname)
      if direntry == None:
        newdirentry = {
                    'name': dirname, 
                    'l': 0,
                    'c0': fentry['s'], 
                    'c1': fentry['t'], 
                    'c2': fentry['n'], 
                    'c3': fentry['e'],
                    'children': [entry]
                   }
        dirdict[dirname] = newdirentry
      else:
        direntry['c0'] += fentry['s']
        direntry['c1'] += fentry['t']
        direntry['c2'] += fentry['n']
        direntry['c3'] += fentry['e']
        direntry['children'].append(entry)

    for d in dirdict:
      data['children'].append(dirdict[d])
               
    #
    # Barf everything to disk
    #
    json_str = json.dumps(data, indent=1)
    file.write(json_str)
    file.close()

  #
  # Emit the global system information pie
  #
  def emit_general_json(self, state, basedirname, dirname, filename):
    if dirname == '':
      fname = basedirname + '/' + filename
    else:
      fname = basedirname + '/' + dirname + '/' + filename
      
    file = open(fname, 'w')

    #
    # Init the data
    #
    data = {
             'metric_selection': 0, 
             'metric_alternatives': [
              [
               'Time Split', 
               0
              ], 
             ], 
             'entity_name': [
              'All Infrastructure'
             ], 
             'entity_alternatives': [
              {'name': 'Overview', 'targetdata':dirname + 'overview.json', 'targetchart':'pie'},
              {'name': 'Process Peers', 'targetdata':dirname + 'graph.json', 'targetchart':'depgraph'},
              {'name': 'Files', 'targetdata':dirname + 'allfiles.json', 'targetchart':'treemap'},
              {'name': 'URLs', 'targetdata':dirname + 'url_overview.json', 'targetchart':'pie'},
              {'name': 'Client Types', 'targetdata':dirname + 'agent_overview.json', 'targetchart':'pie'},
             ],
             'name': 'Overview',
             'data':[]
           }
    
    #
    # Add the 'data' section
    #
    dtable = {'File I/O': state.fileio_counter.copy(), 
                'Network I/O': state.networkio_counter.copy(), 
                'Other': state.uncategorized_counter.copy(), 
                'Processing': state.processing_counter.copy()}

    dtable['File I/O']['t'] += state.iowait_counter['c'][FD_TYPE_FILE]['t']
    dtable['Network I/O']['t'] += state.iowait_counter['c'][FD_TYPE_NET]['t']
    
    sorted_dtable = sorted(dtable.keys(), key=lambda f: (-dtable[f]['t']))

    for i in sorted_dtable:
      data['data'].append({'name': i, 'c0': dtable[i]['t']})

    #
    # Barf everything to disk
    #
    json_str = json.dumps(data, indent=1)
    file.write(json_str)
    file.close()
         
  #
  # Emit information about each of the processes
  # 
  def emit_procs_json(self, state, basedirname, dirname):
    try:
      if not os.path.exists(basedirname + '/' + dirname):
        os.mkdir(basedirname + '/' + dirname)
      if not os.path.exists(basedirname + '/' + dirname + '/procs'):
        os.mkdir(basedirname + '/' + dirname + '/procs')
    except:
      pass
    for p in state.procs_files:
      procdirpath = basedirname + '/' + dirname + '/procs/' + p
      try:
        os.mkdir(procdirpath)
      except:
        pass

      self.emit_files_json(state.procs_files[p]['c'], basedirname, dirname + '/procs', 'files.json')
    
###############################################################################
# TRANSACTION REPORTER CLASS
###############################################################################
class transactparser:  
  def __init__(self, ioprs):
    self.ioprs = ioprs
    self.urls = {}
    self.agents = {}
    self.nodes = {}
    self.links = {}
    self.servers = {}
    self.clients = {}
    self.pure_clients = {}  # clients that are NOT servers as well
    self.pure_servers = {}  # servers that are NOT clients as well
    self.frontend_servers = {}  # clients that are NOT servers as well
    
  #
  # Processing entry point
  #    
  def run(self):
    for trpid in transactions:
      for tr in transactions[trpid]:
        delta = tr['oe'] - tr['is']

        #
        # Add this entry to the URL table
        #        
        url = tr.get('url')
      
        if url == None:
          url = 'IP'
        
        urlentry = self.urls.get(url)
        if urlentry == None:
          newentry = {'t': delta, 'n': 1, 'tgid':tr['proc']['tgid'], 'name':tr['proc']['name'], 'list':[tr]}
          # mark that this transaction is the first in the list for this URL
          tr['listentry'] = 0
          self.urls[url] = newentry
        else:
          urlentry['t'] += delta
          urlentry['n'] += 1
          urlentry['list'].append(tr)
          # mark that the position that this transaction has in the transaction list for this URL
          tr['listentry'] = len(urlentry['list']) - 1
        
        #
        # Add this entry to the agent table
        #        
        agent = tr.get('agent')
             
        if agent != None:
          agententry = self.agents.get(agent)
          if agententry == None:
            newentry = {'t': delta, 'n': 1, 'tgid':tr['proc']['tgid'], 'name':tr['proc']['name'], 'list':[tr]}
            self.agents[agent] = newentry
          else:
            agententry['t'] += delta
            agententry['n'] += 1
            agententry['list'].append(tr)
          
    #
    # Before returning, parse the table and generate the dependencies
    #
    self.generate_graph_info()
        
  def emit(self):
    print '****** URLs ******'    
    for u in self.urls:
      urlentry = self.ioprs.urlstates[u]
      print '%s - n:%d, t:%d' % (u, self.urls[u]['n'], self.urls[u]['t'])

      print '  file io - n:%d, s:%d, t:%d, e:%d' % (urlentry.fileio_counter['n'], urlentry.fileio_counter['s'], urlentry.fileio_counter['t'], urlentry.fileio_counter['e'])
      print '  network io - n:%d, s:%d, t:%d, e:%d' % (urlentry.networkio_counter['n'], urlentry.networkio_counter['s'], urlentry.networkio_counter['t'], urlentry.networkio_counter['e'])
      print '  io wait - n:%d, t:%d' % (urlentry.iowait_counter['n'], urlentry.iowait_counter['t'])
#      print '    file - n:%d, t:%d' % (urlentry['w']['c'][FD_TYPE_FILE]['n'], urlentry['w']['c'][FD_TYPE_FILE]['t'])
#      print '    net - n:%d, t:%d' % (urlentry['w']['c'][FD_TYPE_NET]['n'], urlentry['w']['c'][FD_TYPE_NET]['t'])
#      print '    file+net - n:%d, t:%d' % (urlentry['w']['c'][FD_TYPE_FILE_NET]['n'], urlentry['w']['c'][FD_TYPE_FILE_NET]['t'])
      print '  uncategorized - n:%d, t:%d' % (urlentry.uncategorized_counter['n'], urlentry.uncategorized_counter['t'])
      print '  processing - n:%d, t:%d' % (urlentry.processing_counter['n'], urlentry.processing_counter['t'])

    print '****** AGENTS ******'    
    for u in self.agents:
      agententry = self.ioprs.agentstates[u]
      print '%s - n:%d, t:%d' % (u, self.agents[u]['n'], self.agents[u]['t'])

      print '  file io - n:%d, s:%d, t:%d, e:%d' % (agententry.fileio_counter['n'], agententry.fileio_counter['s'], agententry.fileio_counter['t'], agententry.fileio_counter['e'])
      print '  network io - n:%d, s:%d, t:%d, e:%d' % (agententry.networkio_counter['n'], agententry.networkio_counter['s'], agententry.networkio_counter['t'], agententry.networkio_counter['e'])
      print '  io wait - n:%d, t:%d' % (agententry.iowait_counter['n'], agententry.iowait_counter['t'])
#      print '    file - n:%d, t:%d' % (agententry['w']['c'][FD_TYPE_FILE]['n'], agententry['w']['c'][FD_TYPE_FILE]['t'])
#      print '    net - n:%d, t:%d' % (agententry['w']['c'][FD_TYPE_NET]['n'], agententry['w']['c'][FD_TYPE_NET]['t'])
#      print '    file+net - n:%d, t:%d' % (agententry['w']['c'][FD_TYPE_FILE_NET]['n'], agententry['w']['c'][FD_TYPE_FILE_NET]['t'])
      print '  uncategorized - n:%d, t:%d' % (agententry.uncategorized_counter['n'], agententry.uncategorized_counter['t'])
      print '  processing - n:%d, t:%d' % (agententry.processing_counter['n'], agententry.processing_counter['t'])
      
  #
  # Parses the connection table and extracts relationship information
  #
  def generate_graph_info(self):
    for trpid in transactions:
      #
      # Extract the list of nodes, clients, servers and links
      #
      for tr in transactions[trpid]:
        name = tr['proc']['name']
        peername = tr['rproc']['name']
        self.nodes[name] = 0
        self.nodes[peername] = 0
        
        self.servers[name] = 0
        self.clients[peername] = 0

        if self.links.get(peername) == None:
          self.links[peername] = {name: 0}
        else:
          self.links[peername][name] = 0
    
    #
    # Pure clients are not servers as well.
    # e.g., wget is a pure client, apache (even when it sends requests to 
    # something like a DB) is not
    #
    for c in self.clients:
      if c not in self.servers:
        self.pure_clients[c] = 0

    #
    # Pure servers are not clients as well.
    # e.g., mysql is usually a pure server, apache (when it sends requests to 
    # something like a DB) is not
    #
    for c in self.servers:
      if c not in self.clients:
        self.pure_servers[c] = 0
        
    #
    # Frontend servers are the ones that receive requests from clients or from
    # the external world
    #
    for s in self.servers:
      try:
        for l in self.links:
          for lt in self.links[l]:
            if lt == s:
              if l in self.servers:
                raise SysRtrExcep
            
        self.frontend_servers[s] = 0
      except SysRtrExcep:
        pass
           
  #
  # Emit global info for URLs
  #
  def emit_url_globals_json(self, basedirname, dirname, filename):
    if dirname == '':
      fname = basedirname + '/' + filename
    else:
      fname = basedirname + '/' + dirname + '/' + filename
      
    file = open(fname, 'w')

    #
    # Init the data
    #
    data = {
             'metric_selection': 0, 
             'metric_alternatives': [
              ['Number of Requests', 0], 
              ['Response Time', 1],
              ['I/O Time', 2],
              ['I/O Bytes', 3], 
              ['Network Time', 4],
              ['Network Bytes', 5], 
              ['Processing Time', 6], 
             ], 
             'entity_name': [
              'All Infrastructure'
             ], 
             'entity_alternatives': [
              {'name': 'Overview', 'targetdata':dirname + 'overview.json', 'targetchart':'pie'},
              {'name': 'Process Peers', 'targetdata':dirname + 'graph.json', 'targetchart':'depgraph'},
              {'name': 'Files', 'targetdata':dirname + 'allfiles.json', 'targetchart':'treemap'},
              {'name': 'URLs', 'targetdata':dirname + 'url_overview.json', 'targetchart':'pie'},
              {'name': 'Client Types', 'targetdata':dirname + 'agent_overview.json', 'targetchart':'pie'},
             ],
             'name': 'URLs',
             'data':[]
           }
    
    #
    # Add the 'data' section
    #
    sorted_dtable = sorted(self.urls.keys(), key=lambda f: (-self.urls[f]['t']))

    j = 0
    for i in sorted_dtable:
      if self.urls[i]['name'] not in self.frontend_servers:
        continue 
      
      if j >= TOPX_NENTRIES_TREEMAP:
        break
      j += 1
      urlentry = self.ioprs.urlstates[i]
      data['data'].append({
                           'name': i, 
                           'c0': self.urls[i]['n'],
                           'c1': self.urls[i]['t'],
                           'c2': urlentry.fileio_counter['t'],
                           'c3': urlentry.fileio_counter['s'],
                           'c4': urlentry.networkio_counter['t'],
                           'c5': urlentry.networkio_counter['s'],
                           'c6': urlentry.processing_counter['t'],
                           'click_target': [
                            'data/urls/' + i + '/graph.json', 
                            'depgraph'
                           ], 
                           })

    #
    # Barf everything to disk
    #
    json_str = json.dumps(data, indent=1)
    file.write(json_str)
    file.close()
    
  #
  # Emit global info for URLs
  #
  def emit_agent_globals_json(self, basedirname, dirname, filename):
    if dirname == '':
      fname = basedirname + '/' + filename
    else:
      fname = basedirname + '/' + dirname + '/' + filename
      
    file = open(fname, 'w')

    #
    # Init the data
    #
    data = {
             'metric_selection': 0, 
             'metric_alternatives': [
              ['Number of Requests', 0], 
              ['Response Time', 1],
              ['I/O Time', 2],
              ['I/O Bytes', 3], 
              ['Network Time', 4],
              ['Network Bytes', 5], 
              ['Processing Time', 6], 
             ], 
             'entity_name': [
              'All Infrastructure'
             ], 
             'entity_alternatives': [
              {'name': 'Overview', 'targetdata':dirname + 'overview.json', 'targetchart':'pie'},
              {'name': 'Process Peers', 'targetdata':dirname + 'graph.json', 'targetchart':'depgraph'},
              {'name': 'Files', 'targetdata':dirname + 'allfiles.json', 'targetchart':'treemap'},
              {'name': 'URLs', 'targetdata':dirname + 'url_overview.json', 'targetchart':'pie'},
              {'name': 'Client Types', 'targetdata':dirname + 'agent_overview.json', 'targetchart':'pie'},
             ],
             'name': 'Client Types',
             'data':[]
           }
    
    #
    # Add the 'data' section
    #
    sorted_dtable = sorted(self.agents.keys(), key=lambda f: (-self.agents[f]['t']))

    j = 0
    for i in sorted_dtable:
      if self.agents[i]['name'] not in self.frontend_servers:
        continue 
      
      if j >= TOPX_NENTRIES_TREEMAP:
        break
      j += 1
      agententry = self.ioprs.agentstates[i]
      data['data'].append({
                           'name': i, 
                           'c0': self.agents[i]['n'],
                           'c1': self.agents[i]['t'],
                           'c2': agententry.fileio_counter['t'],
                           'c3': agententry.fileio_counter['s'],
                           'c4': agententry.networkio_counter['t'],
                           'c5': agententry.networkio_counter['s'],
                           'c6': agententry.processing_counter['t'],
                           'click_target': [
                            'data/agents/' + i + '/graph.json', 
                            'depgraph'
                           ], 
                           })

    #
    # Barf everything to disk
    #
    json_str = json.dumps(data, indent=1)
    file.write(json_str)
    file.close()
    
  #
  # Emit the dependency map
  #
  def emit_graph_json(self, basedirname, dirname, filename):    
    if dirname == '':
      fname = basedirname + '/' + filename
    else:
      fname = basedirname + '/' + dirname + '/' + filename
      
    file = open(fname, 'w')

    #
    # Init the data
    #
    data = {'links': [], 
            'entity_name': ['All Infrastructure'], 
            'name': 'Process Peers', 
            'metric_selection': 0,
            'entity_alternatives': [
              {'name': 'Overview', 'targetdata':dirname + 'overview.json', 'targetchart':'pie'},
              {'name': 'Process Peers', 'targetdata':dirname + 'graph.json', 'targetchart':'depgraph'},
              {'name': 'Files', 'targetdata':dirname + 'allfiles.json', 'targetchart':'treemap'},
              {'name': 'URLs', 'targetdata':dirname + 'url_overview.json', 'targetchart':'pie'},
              {'name': 'Client Types', 'targetdata':dirname + 'agent_overview.json', 'targetchart':'pie'},
            ],
            'metric_alternatives': [
              [
               'Processing', 
               0
              ],
              [
               'File I/O', 
               1
              ],
              [
               'Network I/O', 
               2
              ],
              [
               'Other', 
               3
              ],
            ],
            'nodes': [
            ],
            'links': [
            ]
           }
    
    #
    # Add the 'nodes' section
    #
    nodenames = self.nodes.keys()
    j = 0
    npureclient = 0;
    npureserver = 0;
    for tp in nodenames:
      j += 1
      
      c0entry = self.ioprs.gstate.procs_processing.get(tp)
      if c0entry != None:
        c0 = c0entry['t']
      else:
        c0 = 0
        
      c1entry = self.ioprs.gstate.procs_files.get(tp)
      if c1entry != None:
        c1 = c1entry['t']
      else:
        c1 = 0
        
      c2entry = self.ioprs.gstate.procs_conns.get(tp)
      if c2entry != None:
        c2 = c2entry['t']
      else:
        c2 = 0

      #
      # Attribute I/O wait time to the proper category: file or network
      #
      cioentry = self.ioprs.gstate.procs_iowait.get(tp)      
      if cioentry != None:
        fe = cioentry['c'].get(FD_TYPE_FILE)
        if fe != None:
          c1 += fe['t']
        fn = cioentry['c'].get(FD_TYPE_NET)
        if fn != None:
          c1 += fn['t']
        
      c3entry = self.ioprs.gstate.procs_uncategorized.get(tp)
      if c3entry != None:
        c3 = c3entry['t']
      else:
        c3 = 0
      
      #
      # Poor man's algorythm to decide the ball location
      #
      if tp in self.pure_clients:
        x = 100
        y = (npureclient + .5) * (550 / len(self.pure_clients))
        fixed = True
        npureclient += 1
      elif tp in self.pure_servers:
        x = 800
        y = (npureserver + .5) * (550 / len(self.pure_servers))
        fixed = True
        npureserver += 1
      else:
        x = random.random() * 400 + 500
        y = 275
        fixed = False
      
      #
      # Add the entry
      #
      data['nodes'].append({
       'label': tp, 
       'status': 'ok', 
       'weight': 1000, 
       'c0': c0,
       'c1': c1, 
       'c2': c2, 
       'c3': c3, 
       'x': x,
       'y': y, 
       'fixed': fixed,
       'clk_targ': [
       'data/procs/' + tp + '/files.json', 
       'treemap'
       ]
      })
      
    #
    # Add the 'links' section
    #
    for tl in self.links:
      srcindex = nodenames.index(tl)
      for tle in self.links[tl]:
        dstindex = nodenames.index(tle)
      
        #
        # Note: for the moment we simplify and assume that all the connections are
        # bidirectional, which is a reasonably safe assumption for tcp connections
        #
        data['links'].append({
         'status': 'ok', 
         'source': srcindex, 
         'target': dstindex 
        })
        
        data['links'].append({
         'status': 'ok', 
         'source': dstindex, 
         'target': srcindex 
        })

    #
    # Barf everything to disk
    #
    json_str = json.dumps(data, indent=1)
    file.write(json_str)
    file.close()

  #
  # Navigate the graph and build the tree of sub-transactions for a transaction
  #
  def get_child_transactions(self, pid, transaction, nodes, links, level=0):
    for trpid in transactions:
      for tr in transactions[trpid]:
        if tr['rproc']['pid'] == pid:
          if (tr['is'] > transaction['is']) and (tr['oe'] < transaction['oe']):
            name = tr['proc']['name']
            peername = tr['rproc']['name']
            
            nodes[name] = 0
            
            if links.get(peername) == None:
              links[peername] = {name: 0}
            else:
              links[peername][name] = 0
            
            self.get_child_transactions(trpid, tr, nodes, links, level + 1)
  
  #
  # Emit the dependency map for a URL
  #
  def emit_url_graph_json(self, url, filename):    
    file = open(filename, 'w')
    
    #
    # Init the data
    #
    data = {'links': [], 
            'entity_name': [url], 
            'name': 'Process Peers', 
            'metric_selection': 0,
            'entity_alternatives': [
              {'name': 'Overview', 'targetdata':'data/urls/' + url + '/overview.json', 'targetchart':'pie'},
              {'name': 'Process Peers', 'targetdata':'data/urls/' + url + '/graph.json', 'targetchart':'depgraph'},
              {'name': 'Files', 'targetdata':'data/urls/' + url + '/allfiles.json', 'targetchart':'treemap'},
              {'name': 'Requests', 'targetdata':'data/urls/' + url + '/transactions.json', 'targetchart':'pie'},
            ],
            'metric_alternatives': [
              [
               'Processing', 
               0
              ],
              [
               'File I/O', 
               1
              ],
              [
               'Network I/O', 
               2
              ],
              [
               'Other', 
               3
              ],
            ],
            'nodes': [
            ],
            'links': [
            ]
           }
    
    #
    # Add the 'nodes' section
    #
    
    # Navidate the table to build the node and list dictionaries
    nodes = {}
    links = {}
    for trpid in transactions:
      for tr in transactions[trpid]:    
        trurl = tr.get('url')
        if trurl == None:
          trurl = 'IP'
          
        if trurl == url:
          name = tr['proc']['name']
          peername = tr['rproc']['name']
          
          nodes[name] = 0
          nodes[peername] = 0
          links[peername] = {name: 0}
          
          if links.get(peername) == None:
            links[peername] = {name: 0}
          else:
            links[peername][name] = 0
            
          self.get_child_transactions(trpid, tr, nodes, links)
    
    # Gather the values
    # XXX this is broken because it gets the FULL values for each process.
    #     We accept it for the demo
    nodenames = nodes.keys()
    npureclient = 0;
    npureserver = 0;
    j = 0
    for tp in nodenames:
      j += 1
      
      c0entry = self.ioprs.gstate.procs_processing.get(tp)
      if c0entry != None:
        c0 = c0entry['t']
      else:
        c0 = 0
        
      c1entry = self.ioprs.gstate.procs_files.get(tp)
      if c1entry != None:
        c1 = c1entry['t']
      else:
        c1 = 0
        
      c2entry = self.ioprs.gstate.procs_conns.get(tp)
      if c2entry != None:
        c2 = c2entry['t']
      else:
        c2 = 0

      #
      # Attribute I/O wait time to the proper category: file or network
      #
      cioentry = self.ioprs.gstate.procs_iowait.get(tp)      
      if cioentry != None:
        fe = cioentry['c'].get(FD_TYPE_FILE)
        if fe != None:
          c1 += fe['t']
        fn = cioentry['c'].get(FD_TYPE_NET)
        if fn != None:
          c1 += fn['t']
        
      c3entry = self.ioprs.gstate.procs_uncategorized.get(tp)
      if c3entry != None:
        c3 = c3entry['t']
      else:
        c3 = 0
        
      #
      # Poor man's algorythm to decide the ball location
      #
      if tp in self.pure_clients:
        x = 100
        y = (npureclient + .5) * (550 / len(self.pure_clients))
        fixed = True
        npureclient += 1
      elif tp in self.pure_servers:
        x = 800
        y = (npureserver + .5) * (550 / len(self.pure_servers))
        fixed = True
        npureserver += 1
      else:
        x = random.random() * 400 + 500
        y = 275
        fixed = False
      
      #
      # Add the entry
      #
      data['nodes'].append({
       'label': tp, 
       'status': 'ok', 
       'weight': 1000, 
       'c0': c0,
       'c1': c1, 
       'c2': c2, 
       'c3': c3, 
       'x': x, 
       'y': y, 
       'fixed': fixed,
       'clk_targ': [
#       'data/procs/' + tp + '/files.json', 
       '/data/fileops.json', 
       'oplist'
       ]
      })
      
    #
    # Add the 'links' section
    #
    for tl in links:
      srcindex = nodenames.index(tl)
      for tle in links[tl]:
        dstindex = nodenames.index(tle)
      
        #
        # Note: for the moment we simplify and assume that all the connections are
        # bidirectional, which is a reasonably safe assumption for tcp connections
        #
        data['links'].append({
         'status': 'ok', 
         'source': srcindex, 
         'target': dstindex 
        })
        
        data['links'].append({
         'status': 'ok', 
         'source': dstindex, 
         'target': srcindex 
        })

    #
    # Barf everything to disk
    #
    json_str = json.dumps(data, indent=1)
    file.write(json_str)
    file.close()
  
  #
  # Emit the dependency map for all the URLs
  #
  def emit_url_graphs_json(self, directory):
    for url in self.urls:
      self.emit_url_graph_json(url, directory + '/urls/' + url + '/' + 'graph.json')
    
  #
  # Emit the dependency map for a URL
  #
  def emit_agent_graph_json(self, agent, filename):    
    file = open(filename, 'w')
    
    #
    # Init the data
    #
    data = {'links': [], 
            'entity_name': [agent], 
            'name': 'Process Peers', 
            'metric_selection': 0,
            'entity_alternatives': [
              {'name': 'Overview', 'targetdata':'data/agents/' + agent + '/overview.json', 'targetchart':'pie'},
              {'name': 'Process Peers', 'targetdata':'data/agents/' + agent + '/graph.json', 'targetchart':'depgraph'},
              {'name': 'Files', 'targetdata':'data/agents/' + agent + '/allfiles.json', 'targetchart':'treemap'},
              {'name': 'Transactions', 'targetdata':'data/agents/' + agent + '/transactions.json', 'targetchart':'pie'},
            ],
            'metric_alternatives': [
              [
               'Processing', 
               0
              ],
              [
               'File I/O', 
               1
              ],
              [
               'Network I/O', 
               2
              ],
              [
               'Other', 
               3
              ],
            ],
            'nodes': [
            ],
            'links': [
            ]
           }
    
    #
    # Add the 'nodes' section
    #
    
    # Navidate the table to build the node and list dictionaries
    nodes = {}
    links = {}
    for trpid in transactions:
      for tr in transactions[trpid]:    
        tragent = tr.get('agent')
        if tragent == None:
          tragent = 'IP'
          
        if tragent == agent:
          name = tr['proc']['name']
          peername = tr['rproc']['name']
          
          nodes[name] = 0
          nodes[peername] = 0
          links[peername] = {name: 0}
          
          if links.get(peername) == None:
            links[peername] = {name: 0}
          else:
            links[peername][name] = 0
            
          self.get_child_transactions(trpid, tr, nodes, links)
    
    # Gather the values
    # XXX this is broken because it gets the FULL values for each process.
    #     We accept it for the demo
    nodenames = nodes.keys()
    j = 0
    npureclient = 0;
    npureserver = 0;
    for tp in nodenames:
      j += 1
      
      c0entry = self.ioprs.gstate.procs_processing.get(tp)
      if c0entry != None:
        c0 = c0entry['t']
      else:
        c0 = 0
        
      c1entry = self.ioprs.gstate.procs_files.get(tp)
      if c1entry != None:
        c1 = c1entry['t']
      else:
        c1 = 0
        
      c2entry = self.ioprs.gstate.procs_conns.get(tp)
      if c2entry != None:
        c2 = c2entry['t']
      else:
        c2 = 0

      #
      # Attribute I/O wait time to the proper category: file or network
      #
      cioentry = self.ioprs.gstate.procs_iowait.get(tp)      
      if cioentry != None:
        fe = cioentry['c'].get(FD_TYPE_FILE)
        if fe != None:
          c1 += fe['t']
        fn = cioentry['c'].get(FD_TYPE_NET)
        if fn != None:
          c1 += fn['t']
        
      c3entry = self.ioprs.gstate.procs_uncategorized.get(tp)
      if c3entry != None:
        c3 = c3entry['t']
      else:
        c3 = 0
        
      #
      # Poor man's algorythm to decide the ball location
      #
      if tp in self.pure_clients:
        x = 100
        y = (npureclient + .5) * (550 / len(self.pure_clients))
        fixed = True
        npureclient += 1
      elif tp in self.pure_servers:
        x = 800
        y = (npureserver + .5) * (550 / len(self.pure_servers))
        fixed = True
        npureserver += 1
      else:
        x = random.random() * 400 + 500
        y = 275
        fixed = False
      
      #
      # Add the entry
      #
      data['nodes'].append({
       'label': tp, 
       'status': 'ok', 
       'weight': 1000, 
       'c0': c0,
       'c1': c1, 
       'c2': c2, 
       'c3': c3, 
       'x': x, 
       'y': y, 
       'fixed': fixed,
       'clk_targ': [
#       'data/procs/' + tp + '/files.json', 
       '/data/fileops.json', 
       'oplist'
       ]
      })
      
    #
    # Add the 'links' section
    #
    for tl in links:
      srcindex = nodenames.index(tl)
      for tle in links[tl]:
        dstindex = nodenames.index(tle)
      
        #
        # Note: for the moment we simplify and assume that all the connections are
        # bidirectional, which is a reasonably safe assumption for tcp connections
        #
        data['links'].append({
         'status': 'ok', 
         'source': srcindex, 
         'target': dstindex 
        })
        
        data['links'].append({
         'status': 'ok', 
         'source': dstindex, 
         'target': srcindex 
        })

    #
    # Barf everything to disk
    #
    json_str = json.dumps(data, indent=1)
    file.write(json_str)
    file.close()
  
  #
  # Emit the dependency map for all the agents
  #
  def emit_agent_graphs_json(self, directory):
    for agent in self.agents:
      self.emit_agent_graph_json(agent, directory + '/agents/' + agent + '/' + 'graph.json')

  #
  # Emit the transaction piechart for a url
  #
  def emit_url_transaction(self, url, directory):    
    file = open(directory + '/urls/' + url + '/' + 'transactions.json', 'w')
        
    #
    # Init the data
    #
    data = {
             'metric_selection': 0, 
             'metric_alternatives': [
              [
               'Time Split', 
               0
              ], 
             ], 
             'entity_name': [
              'All Infrastructure'
             ], 
             'entity_alternatives': [
              {'name': 'Overview', 'targetdata':'data/urls/' + url + '/overview.json', 'targetchart':'pie'},
              {'name': 'Process Peers', 'targetdata':'data/urls/' + url + '/graph.json', 'targetchart':'depgraph'},
              {'name': 'Files', 'targetdata':'data/urls/' + url + '/allfiles.json', 'targetchart':'treemap'},
              {'name': 'Requests', 'targetdata':'data/urls/' + url + '/transactions.json', 'targetchart':'pie'},
             ],
             'name': 'Overview',
             'data':[]
           }
    
    #
    # Add the 'data' section
    #
    j = 0
    for t in self.urls[url]['list']:
      j += 1
      data['data'].append({
                           'name': str(j), 
                           'c0': (t['oe'] - t['is']),
                           'click_target': [
                            'data/urls/' + url + '/transactions/' + str(j - 1) + '.json', 
                            'oplist'
                           ]
                           })
    
    #
    # Barf everything to disk
    #
    json_str = json.dumps(data, indent=1)
    file.write(json_str)
    file.close()

  #
  # Emit the dependency map for all the URLs
  #
  def emit_url_transactions(self, directory):
    for url in self.urls:
      self.emit_url_transaction(url, directory)

###############################################################################
# TRANSACTION REPORTER CLASS
###############################################################################
class transact_event_emitter:  
  def __init__(self, ioprs, trprs):
    self.ioprs = ioprs
    self.trprs = trprs

  def emit_url_transaction(self, url, directory):
    if not os.path.exists(directory + 'transactions'):
      os.mkdir(directory + 'transactions')

    for tr in self.trprs.urls[url]['list']:
      fname = directory + 'transactions/' + str(tr['listentry']) + '.json'
      file = open(fname, 'w')
      starttime = 0
      eventnum = 0
      ncomms = 0
      comm_ids = {}
      
      data = {
               "hierarchy_level": 2, 
               "name": "ciao", 
               "entity_name": [
                "/db1.php"
               ], 
               'metric_selection': 0, 
               'metric_alternatives': [
                [
                 'Process Colors', 
                 0
                ],
                [
                 'Event Colors', 
                 1
                ], 
                [
                 'Error Colors', 
                 2
                ], 
               ], 
               'entity_name': [
                'All Infrastructure'
               ], 
               'entity_alternatives': [
                {'name': 'Event List', 'targetdata':'data/urls/overview.json', 'targetchart':'pie'},
               ],
               'name': 'Event List',
               'oplists':{},
               'fulllist':[]
             }

      stime = tr['is']
      etime = tr['oe']
  
      for s in syscalls:
        pid = s['pid']
        ts = s['ts']
                
        if ts < stime or ts > etime:
          continue
        
        if starttime == 0:
          starttime = ts
          
        #
        # If this event is inside a transaction, find the transaction
        #
        trans = lookup_transaction(pid, ts)
        if trans != None:
          if trans == tr or navigate_transactions(trans, tr) == True:
            #
            # Either this event is part of the tr transaction, or it's part of a 
            # transaction that is a child of tr
            #
            comm = s['comm']
            pid = s['pid']
            name = s['name']
            direction = s['dir']
            cname = s['name']
            if cname == 'syscall':
              cname = s['pars']['name']['v']
            pstr = ''
            ecol = 0
            for p in s['pars']:
              val = s['pars'][p]['v']
              pstr  += (p + '=' + val + ' ')
              if p == 'res' or p == 'fd':
                if int(val) < 0:
                  if comm != 'httpd':
                    a = 33
                  ecol = 4
              if s['pars'][p].get('r') != None:
                pstr  += ('(' + s['pars'][p]['r'] + ') ')
                
      
            url = trans.get('url')
                    
            #
            # See if the process is already in the list
            #
            commentry = data['oplists'].get(comm)
            
            if commentry == None:
              commentry = []
              data['oplists'][comm] = commentry
              comm_ids[comm] = ncomms
              ncomms += 1

            data['fulllist'].append([comm, len(commentry)])
            commentry.append({'n':eventnum,
                              's':(ts - starttime) / 1000000000, 
                              'ns':(ts - starttime) % 1000000000, 
                              't': cname, 
                              'd': direction,
                              'p': pid,
                              'a': pstr,
                              'c0': comm_ids[comm], # the process ID
                              'c1': 1,
                              'c2': ecol,
                            })
            eventnum += 1
            
      #
      # Barf everything to disk
      #
      json_str = json.dumps(data, indent=1)
      file.write(json_str)
      file.close()

  def emit(self, directory):
      for url in self.trprs.urls:
        self.emit_url_transaction(url, directory + '/urls/' + url + '/')
      
###############################################################################
# Main code
###############################################################################

#
# Convert the transaction list to our friendly format
#
refactor_transactions()

iop = ioparser()
trp = transactparser(iop)
ee = transact_event_emitter(iop, trp)

#
# Do the IO parsing
#
iop.run()
iop.emit('../../../ui/frontend2/', 'data/')

#
# Do the transaction parsing
#
trp.run()
trp.emit_url_transactions('../../../ui/frontend2/data/')
trp.emit()
trp.emit_url_globals_json('../../../ui/frontend2/', 'data/', 'url_overview.json')
trp.emit_agent_globals_json('../../../ui/frontend2/', 'data/', 'agent_overview.json')
trp.emit_graph_json('../../../ui/frontend2/', 'data/', 'graph.json')
trp.emit_url_graphs_json('../../../ui/frontend2/data/')
trp.emit_agent_graphs_json('../../../ui/frontend2/data/')

#
# Extrace the per-transaction events
#
ee.emit('../../../ui/frontend2/data/')