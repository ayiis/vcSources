#include <malloc.h>
#define MAX_NAMELEN 64

typedef struct node
{
	char data[MAX_NAMELEN];
	struct node *pNext;
}Node;

Node *InitLink()
{
	Node *head;
	head = (Node *)malloc(sizeof(Node));
	head->pNext = NULL;
	return head;
}  

void Insert(Node *list, char* data)
{
	Node *pNode = (Node *)malloc(sizeof(Node));
	strncpy(pNode->data,data,MAX_NAMELEN);
	pNode->pNext=list->pNext;
	list->pNext = pNode;
}
