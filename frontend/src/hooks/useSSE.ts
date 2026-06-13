import { useEffect, useRef, useState } from 'react';
import { API_BASE } from '../config';
import type { AgentEvent } from '../types';

export function useSSE(sessionId: string | null) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [done, setDone] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    esRef.current?.close();
    esRef.current = null;

    if (!sessionId) {
      setEvents([]);
      setDone(false);
      return;
    }

    setEvents([]);
    setDone(false);

    const es = new EventSource(`${API_BASE}/stream/${sessionId}`);
    esRef.current = es;

    es.onmessage = (e) => {
      try {
        const event: AgentEvent = JSON.parse(e.data);
        setEvents((prev) => [...prev, event]);
        if (event.agent === 'pipeline' && event.status === 'done') {
          setDone(true);
          es.close();
        }
      } catch {
        /* ignore malformed events */
      }
    };

    es.onerror = () => {
      setDone(true);
      es.close();
    };

    return () => es.close();
  }, [sessionId]);

  return { events, done };
}
