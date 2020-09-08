
class watchdog_state
{
public:
    watchdog_state() noexcept:
        m_pid(0),
        m_memory_used(0),
        m_last_loop_s(0)
    {}

    pid_t pid() const noexcept { return m_pid.load(); }
    uint64_t memory_used() const noexcept { return m_memory_used.load(); }
    uint64_t last_loop_s() const noexcept { return m_last_loop_s.load(); }

    void reset(pid_t pid, uint64_t memory_used, uint64_t last_loop_s)
    {
        m_memory_used.store(memory_used);
        m_last_loop_s.store(last_loop_s);
        m_pid.store(pid);
    }

    void reset()
    {
        reset(0, 0, 0);
    }

    bool valid() const
    {
        return m_pid.load() > 0;
    }

    const std::string& name() const
    {
        return m_name;
    }

private:
    // careful here - only app should access this function
    // at a well-defined time (preferably immediately after object
    // creation); the name string will be read from subprocess
    // logger thread
    void set_name(const std::string& name)
    {
        m_name = name;
    }

    std::atomic<pid_t> m_pid;
    std::atomic<uint64_t> m_memory_used;
    std::atomic<uint64_t> m_last_loop_s;
    std::string m_name;

    // Dragent calls set_name just after construction
    friend class dragent_app;
    friend class agentone_app;
};

