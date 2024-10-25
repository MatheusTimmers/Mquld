#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "mqueue"
#define CLASS_NAME "mquld"
#define SUCCESS 0

// Declaracao

// Infos do modulo
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matheus Timmers, Matheus Robin e Pedro de Ros");
MODULE_DESCRIPTION("mquld - Message Queue Under Linux Driver");

// Variaveis globais
static int max_messages = -1;
static int max_message_size = -1;
static int major_number;
static int device_open = 0;
static struct class *mquld_class = NULL;
static struct device *mquld_device = NULL;

static LIST_HEAD(process_list);
static DEFINE_MUTEX(mquld_mutex);

// Parametros da inicialiazacao do modulo
module_param(max_messages, int, S_IRUGO);
module_param(max_message_size, int, S_IRUGO);

MODULE_PARM_DESC(max_messages, "Número máximo de mensagens por processo");
MODULE_PARM_DESC(max_message_size,
                 "Tamanho máximo de cada mensagem (em bytes)");

#define NAME_SIZE 30

// Estruturas
struct message_s {
  struct list_head list_m;
  char* data;
  unsigned int size;
};

struct process_entry {
  pid_t pid;
  char name[NAME_SIZE];
  struct list_head message_queue;
  struct list_head list_p;
  int message_count;
};

// Implementacao

static void list_delete_head(struct process_entry *proc_entry) {
    struct message_s *msg = list_first_entry(&proc_entry->message_queue, struct message_s, list_m);
    list_del(&msg->list_m);
    kfree(msg);
}

static void free_process(struct process_entry *proc_entry) {
    struct message_s *msg;
    struct list_head *msg_pos, *msg_q;

    list_for_each_safe(msg_pos, msg_q, &proc_entry->message_queue) {
        msg = list_entry(msg_pos, struct message_s, list_m);
        kfree(msg->data);
        kfree(msg);
    }
    list_del(&proc_entry->list_p);
    kfree(proc_entry);
}

static struct process_entry *find_process_by_name(char *name) {
  struct process_entry *proc_entry;
  struct list_head *pos;

  list_for_each_entry(proc_entry, &process_list, list_p) {
    if (strcmp(proc_entry->name, name) == 0) {
      return proc_entry;
    }
  }
  return NULL;
}

static struct process_entry *find_process_by_pid(pid_t pid) {
    struct process_entry *proc_entry;

    list_for_each_entry(proc_entry, &process_list, list_p) {
        if (proc_entry->pid == pid) {
            return proc_entry;
        }
    }

    return NULL;
}

static struct process_entry *find_or_register_process(pid_t pid, char *name) {
  struct process_entry *proc_entry;

  mutex_lock(&mquld_mutex);
  proc_entry = find_process_by_name(name);

  // Se o processo nao existir cria
  if (!proc_entry) {
    proc_entry = kmalloc(sizeof(struct process_entry), GFP_KERNEL);
    if (!proc_entry) {
      mutex_unlock(&mquld_mutex);
      return NULL;
    }

    proc_entry->pid = pid;
    strncpy(proc_entry->name, name, NAME_SIZE - 1);
    proc_entry->name[NAME_SIZE - 1] = '\0';
    proc_entry->message_count = 0;

    INIT_LIST_HEAD(&proc_entry->message_queue);
    INIT_LIST_HEAD(&proc_entry->list_p);

    list_add(&proc_entry->list_p, &process_list);
    printk(KERN_INFO "mquld: Process with pid %d and name %s registered.\n",
           pid, proc_entry->name);
  } else {
    printk(KERN_INFO "mquld: Process with pid %d is already registered.\n",
           pid);
  }

  mutex_unlock(&mquld_mutex);
  return proc_entry;
}

static int send_message_to_process(struct process_entry *target_entry,
                                   char *message) {
  if (target_entry->message_count >= max_messages) {
    list_delete_head(target_entry);
    target_entry->message_count--;
  }

  struct message_s *new_msg = kmalloc(sizeof(struct message_s), GFP_KERNEL);
  if (!new_msg) {
    printk(KERN_ALERT "mquld: Failed to allocate memory for message.\n");
    return -ENOMEM;
  }

  new_msg->data = kmalloc(max_message_size, GFP_KERNEL);
  if (!new_msg->data) {
      kfree(new_msg);
      printk(KERN_ALERT "mquld: Failed to allocate memory for message data.\n");
      return -ENOMEM;
  }
  strncpy(new_msg->data, message, max_message_size - 1);
  new_msg->data[max_message_size - 1] = '\0';
  new_msg->size = strlen(new_msg->data);

  list_add_tail(&new_msg->list_m, &target_entry->message_queue);
  target_entry->message_count++;

  printk(KERN_INFO "mquld: Message sent to process %s: %s\n",
         target_entry->name, message);
  return 0;
}

// Função chamada quando o módulo é aberto
static int mquld_open(struct inode *inode, struct file *file) {
  if (device_open) return -EBUSY;

  device_open++;
  try_module_get(THIS_MODULE);

  return SUCCESS;
}

// Função que libera o módulo
static int mquld_release(struct inode *inode, struct file *file) {
  device_open--;
  module_put(THIS_MODULE);

  return SUCCESS;
}

// Função de leitura do módulo
static ssize_t mquld_read(struct file *file, char __user *buf, size_t count,
                          loff_t *ppos) {
  struct process_entry *proc_entry;
  struct message_s *msg;
  size_t message_size;
  int ret;

  pid_t pid = task_pid_nr(current);

  proc_entry = find_process_by_pid(pid);
  if (!proc_entry) {
    printk(
        KERN_ALERT
        "mquld: Unregistered process, failed to find or register.\n");
    return -EFAULT;
  }

  mutex_lock(&mquld_mutex);

  if (list_empty(&proc_entry->message_queue)) {
    printk(KERN_INFO "mquld: No messages for process %s (PID %d).\n",
           proc_entry->name, pid);
    mutex_unlock(&mquld_mutex);
    return 0;
  }

  msg = list_first_entry(&proc_entry->message_queue, struct message_s, list_m);

  message_size = min(count, (size_t)msg->size);

  ret = copy_to_user(buf, msg->data, message_size);
  if (ret != 0) {
    printk(KERN_ALERT
           "mquld: Failed to copy data to user space.\n");
    mutex_unlock(&mquld_mutex);
    return -EFAULT;
  }

  list_del(&msg->list_m);
  kfree(msg->data);
  kfree(msg);
  proc_entry->message_count--;

  mutex_unlock(&mquld_mutex);

  printk(KERN_INFO
         "mquld: Read successfully for process %s (PID %d), "
         "%zu bytes read.\n",
         proc_entry->name, pid, message_size);

  return message_size;
}

// Função de escrita do módulo
static ssize_t mquld_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos) {
  char *kbuf;
  struct process_entry *proc_entry;

  kbuf = kmalloc(count + 1, GFP_KERNEL);
  if (!kbuf) {
    printk(KERN_ALERT "mquld: Failed to allocate memory for command.\n");
    return -ENOMEM;
  }

  if (copy_from_user(kbuf, buf, count)) {
    kfree(kbuf);
    return -EFAULT;
  }
  kbuf[count] = '\0';

  if (strncmp(kbuf, "/reg ", 5) == 0) {
    char *name = kbuf + 5;

    if (strlen(name) >= NAME_SIZE) {
      printk(KERN_ALERT "mquld: Process name too long.\n");
      kfree(kbuf);
      return -EINVAL;
    }

    proc_entry = find_or_register_process(current->pid, name);
    if (!proc_entry) {
      kfree(kbuf);
      printk(KERN_ALERT "mquld: Failed to register process entry.\n");
      return -ENOMEM;
    }
  } else if (strncmp(kbuf, "/unreg ", 7) == 0) {
    char *name = kbuf + 7;

    proc_entry = find_process_by_name(name);
    if (!proc_entry) {
      printk(KERN_ALERT "mquld: Process %s not found.\n", name);
      kfree(kbuf);
      return -ESRCH;
    }

    mutex_lock(&mquld_mutex);
    free_process(proc_entry);
    mutex_unlock(&mquld_mutex);

    printk(KERN_INFO "mquld: Process %s unregistered and removed.\n", name);
  } else {
    char *name = kbuf + 1;
    char *message = strchr(name, ' ');

    if (strlen(message) > max_message_size) {
      printk(KERN_ALERT "mquld: Message too large for process %s.\n", name);
      return -EINVAL;
    }

    if (!message) {
      printk(KERN_ALERT "mquld: Invalid message format.\n");
      kfree(kbuf);
      return -EINVAL;
    }

    *message = '\0';
    message++;

    proc_entry = find_process_by_name(name);
    if (!proc_entry) {
      printk(KERN_ALERT "mquld: Target process %s not found.\n", name);
      kfree(kbuf);
      return -ESRCH;
    }

    int ret = send_message_to_process(proc_entry, message);
    if (ret < 0) {
      kfree(kbuf);
      return ret;
    }
  }

  kfree(kbuf);
  return count;
}

// Operações suportadas pelo módulo
static struct file_operations fops = {.owner = THIS_MODULE,
                                      .open = mquld_open,
                                      .read = mquld_read,
                                      .write = mquld_write,
                                      .release = mquld_release};

// Função chamada na criação do módulo
static int __init mquld_init(void) {

  if (max_messages == -1 && max_message_size == -1) {
    printk(KERN_ALERT "mquld: Not loaded. Pass two integers!\n");
    return -EINVAL;
  }

  major_number = register_chrdev(0, DEVICE_NAME, &fops);
  if (major_number < 0) {
    printk(KERN_ALERT "mquld: Failed to register a major number.\n");
    return major_number;
  }

  mquld_class = class_create(THIS_MODULE, CLASS_NAME);
  if (IS_ERR(mquld_class)) {
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_ALERT "mquld: Failed to register device class.\n");
    return PTR_ERR(mquld_class);
  }

  mquld_device = device_create(mquld_class, NULL, MKDEV(major_number, 0), NULL,
                               DEVICE_NAME);
  if (IS_ERR(mquld_device)) {
    class_destroy(mquld_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_ALERT "mquld: Failed to create the device.\n");
    return PTR_ERR(mquld_device);
  }

  printk(KERN_INFO "mquld: Device class created successfully.\n");
  return SUCCESS;
}

// Função chamada na remoção do módulo
static void __exit mquld_exit(void) {
  struct process_entry *proc_entry;
  struct list_head *pos, *q;

  mutex_lock(&mquld_mutex);
  list_for_each_safe(pos, q, &process_list) {
    proc_entry = list_entry(pos, struct process_entry, list_p);
    free_process(proc_entry);
  }
  mutex_unlock(&mquld_mutex);

  device_destroy(mquld_class, MKDEV(major_number, 0));
  class_unregister(mquld_class);
  class_destroy(mquld_class);
  unregister_chrdev(major_number, DEVICE_NAME);
  printk(KERN_INFO "mquld: Module unloaded.\n");
}

module_init(mquld_init);
module_exit(mquld_exit);