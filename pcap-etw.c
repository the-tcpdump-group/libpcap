#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "pcap-int.h"

#define MAX_SESSIONS 64
#define MAX_SESSION_NAME_LEN 1024
#define MAX_LOGFILE_PATH_LEN 1024

static char nosup[] = "live packet capture not supported on this system";

/*
 *	A double linked list for buffered
 *	ETW Events for current session
 */
typedef struct _pcap_etw_list_event_t
{
	struct _pcap_etw_list_event_t* next;
	struct _pcap_etw_list_event_t* previous;
	PEVENT_HEADER	event;
} pcap_etw_list_event_t;

/*
 *	A list Type thread safe
 */
typedef struct _pcap_etw_list_t
{
	pcap_etw_list_event_t head;
	pcap_etw_list_event_t tail;
	HANDLE mutex;
	HANDLE wait;
} pcap_etw_list_t;

/*
 *	A context for ETW capture
 */
typedef struct _pcap_etw_t 
{
	TRACEHANDLE	trace;
	HANDLE		thread;
	pcap_etw_list_t events;
	char	session_name[MAX_SESSION_NAME_LEN];
} pcap_etw_t;

/*
 * Initialize an empty list
 */
static int
pcap_etw_list_init(pcap_etw_list_t* self)
{
	self->head.next = &self->tail;
	self->tail.previous = &self->head;
	self->mutex = CreateMutex(NULL, FALSE, NULL);
	if (INVALID_HANDLE_VALUE == self->mutex)
	{
		return (-1);
	}
	self->wait = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (INVALID_HANDLE_VALUE == self->wait)
	{
		return (-1);
	}
	return (0);
}

/*
 *	Push element to the end of list
 *	It will ordered event from a timestamp criteria
 */
static void
pcap_etw_list_push(pcap_etw_list_t* self, pcap_etw_list_event_t* element)
{
	WaitForSingleObject(self->mutex, INFINITE);
	pcap_etw_list_event_t* iter = NULL;

	for (iter = self->head.next; iter != &self->tail; iter = iter->next)
	{
		if (element->event->TimeStamp.QuadPart > iter->event->TimeStamp.QuadPart )
		{
			break;
		}
	}

	element->next = iter;
	element->previous = iter->previous;
	element->previous->next = element;
	element->next->previous = element;
	ReleaseMutex(self->mutex);
	SetEvent(self->wait);
}

/*
 *	Pop list from the head
 *	Return NULL if list is empty
 */
static pcap_etw_list_event_t*
pcap_etw_list_pop(pcap_etw_list_t* self)
{
	// empty list
	if (self->head.next == &self->tail)
	{
		return NULL;
	}
	WaitForSingleObject(self->mutex, INFINITE);
	pcap_etw_list_event_t* result = self->tail.previous;
	result->previous->next = &self->tail;
	self->tail.previous = result->previous;
	ReleaseMutex(self->mutex);
	return result;
}

/*
 * Start listener for trace session
 */
static DWORD
pcap_etw_listener(LPVOID lpThreadParameter)
{
	ProcessTrace(&(TRACEHANDLE)lpThreadParameter, 1, NULL, NULL);
	return 0;
}

/*
 *	This is the main callback for each event
 *	This function serialize event as in ETL file 
 *	and push into event into list
 */
static VOID
pcap_etw_process_event(PEVENT_RECORD EventRecord)
{
	pcap_etw_t* etw = (pcap_etw_t*)EventRecord->UserContext;
	pcap_etw_list_event_t* element = (pcap_etw_list_event_t*)malloc(sizeof(pcap_etw_list_event_t));

	if (NULL == element) {
		return;
	}

	ZeroMemory(element, sizeof(pcap_etw_list_event_t));

	UINT32 extended_data_size = 0;
	for (USHORT i = 0; i < EventRecord->ExtendedDataCount; i++) {
		extended_data_size += sizeof(USHORT) + sizeof(USHORT) + EventRecord->ExtendedData[i].DataSize;
	}

	UCHAR* extended_data = (UCHAR*)malloc(extended_data_size);

	if (extended_data == NULL) {
		return;
	}

	size_t offset = 0;
	for (USHORT i = 0; i < EventRecord->ExtendedDataCount; i++) {

		EVENT_HEADER_EXTENDED_DATA_ITEM data = EventRecord->ExtendedData[i];
		memcpy(extended_data + offset, &data.ExtType, sizeof(USHORT));
		offset += sizeof(USHORT);
		memcpy(extended_data + offset, &data.DataSize, sizeof(USHORT));
		offset += sizeof(USHORT);
		memcpy(extended_data + offset, (UCHAR*)data.DataPtr, data.DataSize);
		offset += data.DataSize;
	}

	EventRecord->EventHeader.Size = (USHORT)(sizeof(EVENT_HEADER) + sizeof(USHORT) + extended_data_size + EventRecord->UserDataLength);
	element->event = malloc(EventRecord->EventHeader.Size);

	if (NULL == element->event) {
		return;
	}

	ZeroMemory(element->event, EventRecord->EventHeader.Size);

	memcpy(element->event, &EventRecord->EventHeader, sizeof(EVENT_HEADER));
	memcpy((uint8_t*)element->event + sizeof(EVENT_HEADER), &extended_data_size, sizeof(USHORT));
	memcpy((uint8_t*)element->event + sizeof(EVENT_HEADER) + sizeof(USHORT), extended_data, extended_data_size);
	memcpy((uint8_t*)element->event + sizeof(EVENT_HEADER) + sizeof(USHORT) + extended_data_size, EventRecord->UserData, EventRecord->UserDataLength);

	pcap_etw_list_push(&etw->events, element);
}

static BOOL 
pcap_etw_buffer_event(PEVENT_TRACE_LOGFILE buf)
{

	printf("Event list %d\n", buf->EventsLost);
	return TRUE;
}

/*
 *	Create a consumer for the targeted session
 */
static int
pcap_activate_op_etw(pcap_t *self)
{
	pcap_etw_t* etw = (pcap_etw_t*)self->priv;
	
	EVENT_TRACE_LOGFILE evt_config;
	ZeroMemory(&evt_config, sizeof(EVENT_TRACE_LOGFILE));
	evt_config.LoggerName = etw->session_name;
	evt_config.LogFileName = NULL;	// indicates a real-time session rather than a logfile
	evt_config.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
	evt_config.EventRecordCallback = pcap_etw_process_event;
	evt_config.BufferCallback = pcap_etw_buffer_event;
	evt_config.Context = etw; // Etw context

	// Get a handle to the trace session:
	etw->trace = OpenTrace(&evt_config);
	if (INVALID_PROCESSTRACE_HANDLE == etw->trace)
	{
		snprintf(self->errbuf, PCAP_ERRBUF_SIZE, "Unable to open trace");
		return (-1);
	}

	etw->thread = CreateThread(NULL, 0,	pcap_etw_listener, (LPVOID)etw->trace, 0, NULL);
	if (INVALID_HANDLE_VALUE == etw->thread)
	{
		snprintf(self->errbuf, PCAP_ERRBUF_SIZE, "Unable to create a thread listener");
		return (-1);
	}

	return (0);
}

/*
 *	Use the software base filtering engine
 */
static int
pcap_setfilter_op_etw(pcap_t *p, struct bpf_program *fp)
{
	return install_bpf_program(p, fp);
}

/*
 *	Check stat for this layer capture
 */
static int
pcap_stats_etw(pcap_t *p, struct pcap_stat *ps)
{
	ps->ps_drop = 0;
	//ps->ps_recv = 0;
	return (0);
}

/*
 *	Read operation pending list event from the recorded list
 */
static int
pcap_read_op_etw(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	pcap_etw_t* etw = (pcap_etw_t*)p->priv;
	int n = 0;
	for (n = 0; n < cnt; n++)
	{
		pcap_etw_list_event_t* element = NULL;
		// no more elements
		while ((element = pcap_etw_list_pop(&etw->events)) == NULL)
		{
			DWORD status = WaitForSingleObject(etw->events.wait, 1000);
			switch (status)
			{
			case WAIT_OBJECT_0:
				continue;
			case WAIT_TIMEOUT:
				return (n);
			case WAIT_FAILED:
				return (-1);
			}
			
		}

		struct pcap_pkthdr header;
		header.caplen = element->event->Size;
		header.len = element->event->Size;

		/* convert between timestamp formats */
		ULONGLONG ts = element->event->TimeStamp.QuadPart;
		header.ts.tv_sec = (int)(ts >> 32);
		ts = (ts & 0xffffffffi64) * 1000000;
		ts += 0x80000000; /* rounding */
		header.ts.tv_usec = (int)(ts >> 32);
		if (header.ts.tv_usec >= 1000000) {
			header.ts.tv_usec -= 1000000;
			header.ts.tv_sec++;
		}

		p->stat.ps_recv++;

		callback(user, &header, (u_char*)element->event);

		free(element->event);
		free(element);
	}
	
	return (n);
}

/*
 *	Create new etw interface
 */
pcap_t *
pcap_create_interface(const char *device _U_, char *ebuf)
{
	pcap_t *handle = PCAP_CREATE_COMMON(ebuf, pcap_etw_t);
	if (handle == NULL)
		return NULL;

	handle->activate_op = pcap_activate_op_etw;
	handle->setfilter_op = pcap_setfilter_op_etw;
	handle->stats_op = pcap_stats_etw;
	handle->read_op = pcap_read_op_etw;
	handle->snapshot = MAXIMUM_SNAPLEN;
	handle->linktype = DLT_USER0;

	pcap_etw_t* etw = (pcap_etw_t*)handle->priv;
	pcap_etw_list_init(&etw->events);
	// Device name is the session name
	pcap_strlcpy(etw->session_name, device, MAX_SESSION_NAME_LEN);

	return (handle);
}

/*
 *	Actually create an interface for each running ETW session
 */
int
pcap_platform_finddevs(pcap_if_list_t *devlistp _U_, char *errbuf _U_)
{
	ULONG properties_size = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_SESSION_NAME_LEN * sizeof(WCHAR)) + (MAX_LOGFILE_PATH_LEN * sizeof(WCHAR));
	ULONG buffer_size = properties_size * MAX_SESSIONS;
	PEVENT_TRACE_PROPERTIES buffer = (PEVENT_TRACE_PROPERTIES)malloc(buffer_size);

	if (NULL == buffer)
	{
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unable to allocate memory");
		return (-1);
	}

	ZeroMemory(buffer, buffer_size);

	PEVENT_TRACE_PROPERTIES sessions[MAX_SESSIONS];
	for (USHORT i = 0; i < MAX_SESSIONS; i++)
	{
		sessions[i] = (EVENT_TRACE_PROPERTIES*)((BYTE*)buffer + (i*properties_size));
		sessions[i]->Wnode.BufferSize = properties_size;
		sessions[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		sessions[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_SESSION_NAME_LEN * sizeof(WCHAR));
	}

	ULONG session_count = 0;
	ULONG status = QueryAllTraces(sessions, (ULONG)MAX_SESSIONS, &session_count);

	if (ERROR_SUCCESS != status)
	{
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unable to query running trace on your system");
		goto cleanup;
	}

	for (USHORT i = 0; i < session_count; i++)
	{
		if (add_dev(devlistp, (char*)sessions[i] + sessions[i]->LoggerNameOffset, PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE, (char*)sessions[i] + sessions[i]->LoggerNameOffset, errbuf) == NULL)
		{
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "Unable to create new interface");
			goto cleanup;
		}
	}

	return (0);

cleanup:
	free(buffer);
	return (-1);
}

/*
 *	No lookup for ETW capture
 */
#ifdef _WIN32
int
pcap_lookupnet(const char *device _U_, bpf_u_int32 *netp _U_,
    bpf_u_int32 *maskp _U_, char *errbuf)
{
	(void)pcap_strlcpy(errbuf, nosup, PCAP_ERRBUF_SIZE);
	return (-1);
}
#endif

/*
 * Libpcap version string.
 */
const char *
pcap_lib_version(void)
{
	return (PCAP_VERSION_STRING);
}
