#define MYMODULE_BDG_NAME       "vale0:"
struct mmreq {
	char mr_name[IFNAMSIZ];
	uint16_t mr_sport;
	uint16_t mr_dport;
	int mr_cmd;
};
